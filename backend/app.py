import base64
import html
import logging
import os

from typing import Any
from urllib.parse import urlparse, urlunparse
from uuid import uuid4

import bleach
import httpx
import oauth
import socketio
import validators

from a2a.client import A2ACardResolver
from a2a.client.auth.interceptor import AuthInterceptor
from a2a.client.client import Client, ClientCallContext, ClientConfig
from a2a.client.client_factory import ClientFactory
from a2a.types import (
    AgentCard,
    Message,
    Part,
    Role,
    SendMessageRequest,
)
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from google.protobuf.json_format import MessageToDict


# ---------------------------------------------------------------------------
# Backward-compatibility: TransportProtocol moved and enum values changed.
# v0.3: TransportProtocol.jsonrpc  (lowercase)
# v1.0: TransportProtocol.JSONRPC  (SCREAMING_SNAKE_CASE)
# ---------------------------------------------------------------------------
try:
    from a2a.utils.constants import TransportProtocol

    _TP_JSONRPC = TransportProtocol.JSONRPC
    _TP_HTTP_JSON = TransportProtocol.HTTP_JSON
    _TP_GRPC = TransportProtocol.GRPC
except (ImportError, AttributeError):
    # Fall back to legacy import path (a2a-sdk < 1.0)
    from a2a.types import (  # type: ignore[attr-defined,no-redef]
        TransportProtocol,
    )

    _TP_JSONRPC = TransportProtocol.jsonrpc  # type: ignore[attr-defined]
    try:
        _TP_HTTP_JSON = TransportProtocol.http_json  # type: ignore[attr-defined]
    except AttributeError:
        _TP_HTTP_JSON = _TP_JSONRPC
    try:
        _TP_GRPC = TransportProtocol.grpc  # type: ignore[attr-defined]
    except AttributeError:
        _TP_GRPC = _TP_JSONRPC


STANDARD_HEADERS = {
    'host',
    'user-agent',
    'accept',
    'content-type',
    'content-length',
    'connection',
    'accept-encoding',
}

# ==============================================================================
# Setup
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

app = FastAPI()
# NOTE: In a production environment, cors_allowed_origins should be restricted
# to the specific frontend domain, not a wildcard '*'.
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
socket_app = socketio.ASGIApp(sio)
app.mount('/socket.io', socket_app)

app.mount('/static', StaticFiles(directory='../frontend/public'), name='static')
templates = Jinja2Templates(directory='../frontend/public')

# ==============================================================================
# State Management
# ==============================================================================

# NOTE: This global dictionary stores state. For a simple inspector tool with
# transient connections, this is acceptable. For a scalable production service,
# a more robust state management solution (e.g., Redis) would be required.
clients: dict[str, tuple[httpx.AsyncClient, Client, AgentCard, str]] = {}

# Holds OAuth tokens per (socket session, security scheme). Kept separate
# from `clients` so the tuple above keeps its shape, and because tokens
# outlive individual A2A client objects.
oauth_service = oauth.OAuthCredentialService()


# ==============================================================================
# Protobuf/Pydantic serialization helpers
# ==============================================================================


def _to_dict(obj: Any) -> dict[str, Any]:
    """Serialize a protobuf Message or Pydantic model to a dict.

    Handles both a2a-sdk v1.0 (protobuf) and legacy v0.3 (Pydantic) objects.
    Raises TypeError for unsupported types.
    """
    # v1.0 protobuf messages have DESCRIPTOR attribute
    if hasattr(obj, 'DESCRIPTOR'):
        return MessageToDict(obj, preserving_proto_field_name=False)
    # Legacy v0.3 Pydantic models
    if hasattr(obj, 'model_dump'):
        return obj.model_dump(exclude_none=True)
    if isinstance(obj, dict):
        return obj
    raise TypeError(f'Cannot serialize {type(obj).__name__} to dict')


def _get_agent_card_dict(card: AgentCard) -> dict[str, Any]:
    """Convert AgentCard to a display-friendly dict, normalizing v1.0 fields."""
    data = _to_dict(card)
    # v1.0: top-level 'url' lives inside supportedInterfaces
    if 'supportedInterfaces' in data and 'url' not in data:
        interfaces = data['supportedInterfaces']
        if interfaces:
            data['url'] = interfaces[0].get('url', '')
    return data


def _get_transport_from_card(card: AgentCard) -> str:
    """Extract the primary transport protocol string from an AgentCard (v1.0 or v0.3)."""
    # v1.0: supported_interfaces list with protocol_binding (or transport)
    try:
        if hasattr(card, 'supported_interfaces') and card.supported_interfaces:
            iface = card.supported_interfaces[0]
            # v1.0 uses protocol_binding; some compat layers may use transport
            binding = getattr(iface, 'protocol_binding', None) or getattr(
                iface, 'transport', None
            )
            if binding:
                return str(binding)
    except (IndexError, AttributeError):
        pass
    # v0.3 legacy fallback
    if hasattr(card, 'preferred_transport') and card.preferred_transport:
        return str(card.preferred_transport)
    return 'JSONRPC'


def _get_input_modes(card: AgentCard) -> list[str]:
    """Extract default input modes from AgentCard (v1.0 or v0.3)."""
    if hasattr(card, 'default_input_modes'):
        modes = list(card.default_input_modes)
        if modes:
            return modes
    return ['text/plain']


def _get_output_modes(card: AgentCard) -> list[str]:
    """Extract default output modes from AgentCard (v1.0 or v0.3)."""
    if hasattr(card, 'default_output_modes'):
        modes = list(card.default_output_modes)
        if modes:
            return modes
    return ['text/plain']


# ==============================================================================
# Socket.IO Event Helpers
# ==============================================================================


async def _emit_debug_log(
    sid: str, event_id: str, log_type: str, data: Any
) -> None:
    """Helper to emit a structured debug log event to the client."""
    await sio.emit(
        'debug_log', {'type': log_type, 'data': data, 'id': event_id}, to=sid
    )


def _extract_context_id_from_event(event: Any) -> str | None:
    """Extract context_id from any of the possible event types."""
    for attr in ('context_id', 'contextId'):
        val = getattr(event, attr, None)
        if val:
            return val
    return None


def _unwrap_stream_response(client_event: Any) -> object:
    """Unwrap a StreamResponse or legacy ClientEvent into the inner payload.

    Supports:
    - a2a-sdk stable 1.0.x+: StreamResponse protobuf yielded directly
    - a2a-sdk v1.0 alpha: tuple[StreamResponse, Task | None]
    - a2a-sdk v0.3: tuple[TaskStatusUpdateEvent | TaskArtifactUpdateEvent, Task] | Message
    """
    payload_fields = ('task', 'message', 'status_update', 'artifact_update')

    if hasattr(client_event, 'DESCRIPTOR') and hasattr(
        client_event, 'WhichOneof'
    ):
        # Stable SDK: StreamResponse protobuf yielded directly
        which = client_event.WhichOneof('payload')
        return (
            getattr(client_event, which)
            if which in payload_fields
            else client_event
        )

    if isinstance(client_event, tuple):
        stream_response, task = client_event[0], client_event[1]
        if hasattr(stream_response, 'DESCRIPTOR'):
            # v1.0 alpha: protobuf tuple
            which = stream_response.WhichOneof('payload')
            if which in payload_fields:
                return getattr(stream_response, which)
            return task if task is not None else stream_response
        # v0.3: first element is the streaming event
        return stream_response

    # v0.3 direct message (non-streaming)
    return client_event


async def _process_a2a_response(
    client_event: Any,
    sid: str,
    request_id: str,
) -> None:
    """Processes a response from the A2A client, validates it, and emits events.

    Supports:
    - a2a-sdk stable 1.0.x+: send_message yields StreamResponse directly
    - a2a-sdk v1.0 alpha: ClientEvent = tuple[StreamResponse, Task | None]
    - a2a-sdk v0.3: ClientEvent = tuple[TaskStatusUpdateEvent | TaskArtifactUpdateEvent, Task] | Message

    Args:
        client_event: The event or message received.
        sid: The session ID associated with the original request.
        request_id: The unique ID of the original request.
    """
    # --- Unwrap the client_event ---
    event: object = _unwrap_stream_response(client_event)

    response_id = (
        getattr(event, 'id', None)
        or getattr(event, 'task_id', request_id)
        or request_id
    )

    # Serialize
    response_data = _to_dict(event)
    response_data['id'] = response_id

    # Normalize kind for frontend (protobuf doesn't have 'kind')
    if 'kind' not in response_data:
        type_name = type(event).__name__
        kind_map = {
            'Task': 'task',
            'Message': 'message',
            'TaskStatusUpdateEvent': 'status-update',
            'TaskArtifactUpdateEvent': 'artifact-update',
        }
        response_data['kind'] = kind_map.get(type_name, 'unknown')

    # Normalize task states: v1.0 uses TASK_STATE_COMPLETED (integer or string)
    # Convert to lowercase for frontend compatibility
    _normalize_task_state(response_data)

    validation_errors = validators.validate_message(response_data)
    response_data['validation_errors'] = validation_errors

    await _emit_debug_log(sid, response_id, 'response', response_data)
    await sio.emit('agent_response', response_data, to=sid)


def _normalize_task_state(data: dict[str, Any]) -> None:
    """Normalize v1.0 SCREAMING_SNAKE_CASE TaskState values to lowercase for frontend.

    v0.3: 'working', 'completed', 'failed', etc.
    v1.0: 'TASK_STATE_WORKING', 'TASK_STATE_COMPLETED', etc. (or integer enum)

    We normalize to lowercase for backward compat with the frontend.
    """
    task_state_map = {
        'TASK_STATE_UNSPECIFIED': 'unknown',
        'TASK_STATE_SUBMITTED': 'submitted',
        'TASK_STATE_WORKING': 'working',
        'TASK_STATE_COMPLETED': 'completed',
        'TASK_STATE_FAILED': 'failed',
        'TASK_STATE_CANCELED': 'canceled',
        'TASK_STATE_CANCELLED': 'canceled',
        'TASK_STATE_INPUT_REQUIRED': 'input-required',
        'TASK_STATE_REJECTED': 'rejected',
        'TASK_STATE_AUTH_REQUIRED': 'auth-required',
    }
    if 'status' in data and isinstance(data['status'], dict):
        state = data['status'].get('state')
        if isinstance(state, str) and state in task_state_map:
            data['status']['state'] = task_state_map[state]
        elif isinstance(state, int):
            # Protobuf serializes enums as ints sometimes
            int_map = {
                0: 'unknown',
                1: 'submitted',
                2: 'working',
                3: 'completed',
                4: 'failed',
                5: 'canceled',
                6: 'input-required',
                7: 'rejected',
                8: 'auth-required',
            }
            data['status']['state'] = int_map.get(state, str(state))


def get_card_resolver(
    client: httpx.AsyncClient, agent_card_url: str
) -> A2ACardResolver:
    """Returns an A2ACardResolver for the given agent card URL."""
    parsed_url = urlparse(agent_card_url)
    base_url = f'{parsed_url.scheme}://{parsed_url.netloc}'
    path_with_query = urlunparse(
        ('', '', parsed_url.path, '', parsed_url.query, '')
    )
    card_path = path_with_query.lstrip('/')
    if card_path:
        card_resolver = A2ACardResolver(
            client, base_url, agent_card_path=card_path
        )
    else:
        card_resolver = A2ACardResolver(client, base_url)

    return card_resolver


def _make_client_config() -> ClientConfig:
    """Build ClientConfig, handling v1.0 and v0.3 API differences.

    v1.0: supported_protocol_bindings param (SCREAMING_SNAKE_CASE enum values)
    v0.3: supported_transports param (lowercase enum values)
    """
    try:
        # v1.0 API
        return ClientConfig(
            supported_protocol_bindings=[
                _TP_JSONRPC,
                _TP_HTTP_JSON,
                _TP_GRPC,
            ],
            use_client_preference=True,
        )
    except TypeError:
        # v0.3 fallback
        return ClientConfig(
            supported_transports=[  # type: ignore[call-arg]
                _TP_JSONRPC,
                _TP_HTTP_JSON,
                _TP_GRPC,
            ],
            use_client_preference=True,
        )


def _make_message(
    role: Any,
    parts: list[Any],
    message_id: str,
    context_id: str | None,
    metadata: dict[str, Any],
) -> Message:
    """Build a Message, compatible with both v1.0 (protobuf) and v0.3 (Pydantic)."""
    kwargs: dict[str, Any] = {
        'role': role,
        'parts': parts,
        'message_id': message_id,
    }
    if context_id:
        kwargs['context_id'] = context_id
    if metadata:
        kwargs['metadata'] = metadata  # type: ignore[assignment]
    return Message(**kwargs)


def _make_text_part(text: str) -> Any:
    """Create a text Part, compatible with v1.0 and v0.3."""
    # v1.0: Part(text=...) — protobuf oneof
    # v0.3: TextPart(text=...) wrapped in Part(root=...)
    try:
        return Part(text=text)  # v1.0
    except (TypeError, AttributeError):
        pass
    # v0.3 fallback
    try:
        from a2a.types import (  # type: ignore[attr-defined] # noqa: PLC0415
            TextPart,
        )

        part_compat = Part
        return part_compat(root=TextPart(text=text))  # type: ignore[call-arg]
    except (TypeError, ImportError, AttributeError):
        return Part(text=text)


def _make_file_part(data: str, mime_type: str) -> Any:
    """Create a file (bytes) Part, compatible with v1.0 and v0.3."""
    # v1.0: Part(raw=bytes, media_type=mime_type)
    # v0.3: FilePart(file=FileWithBytes(bytes=data, mime_type=mime_type))
    try:
        raw_bytes = base64.b64decode(data)
        return Part(raw=raw_bytes, media_type=mime_type)  # v1.0
    except (TypeError, AttributeError):
        pass
    # v0.3 fallback
    try:
        from a2a.types import (  # type: ignore[attr-defined] # noqa: PLC0415
            FilePart,
            FileWithBytes,
        )

        return FilePart(file=FileWithBytes(bytes=data, mime_type=mime_type))  # type: ignore[call-arg]
    except (TypeError, ImportError, AttributeError):
        return Part(raw=base64.b64decode(data), media_type=mime_type)  # type: ignore[call-arg]


def _get_role_user() -> Any:
    """Get the user role constant, compatible with v1.0 and v0.3."""
    # v1.0: Role.ROLE_USER (int enum)
    # v0.3: Role.user (string enum)
    try:
        return Role.ROLE_USER  # type: ignore[attr-defined]
    except AttributeError:
        return Role.user  # type: ignore[attr-defined]


async def _send_message_compat(
    client: Client,
    message: Message,
    context: ClientCallContext | None = None,
) -> Any:
    """Call client.send_message with v1.0 or v0.3 API.

    v1.0: client.send_message(SendMessageRequest(request=message)) -> AsyncIterator[ClientEvent]
    v0.3: client.send_message(message) -> AsyncIterator[ClientEvent]

    The context carries the session id that the OAuth credential service
    needs to look up a token; without it the AuthInterceptor finds nothing
    and the request goes out unauthenticated.
    """
    # v1.0: send_message() requires a SendMessageRequest protobuf wrapper.
    # The wrapper field is "message" (not "request" — that was pre-alpha naming).
    try:
        request = SendMessageRequest(message=message)
        return client.send_message(request, context=context)
    except (TypeError, AttributeError, ValueError):
        # v0.3 fallback: send_message takes a Message directly
        return client.send_message(message, context=context)  # type: ignore[arg-type]


# ==============================================================================
# FastAPI Routes
# ==============================================================================


@app.get('/', response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Serve the main index.html page."""
    return templates.TemplateResponse('index.html', {'request': request})


@app.post('/agent-card')
async def get_agent_card(request: Request) -> JSONResponse:
    """Fetch and validate the agent card from a given URL."""
    # 1. Parse request and get sid. If this fails, we can't do much.
    try:
        request_data = await request.json()
        agent_url = request_data.get('url')
        sid = request_data.get('sid')

        if not agent_url or not sid:
            return JSONResponse(
                content={'error': 'Agent URL and SID are required.'},
                status_code=400,
            )
    except Exception:
        logger.warning('Failed to parse JSON from /agent-card request.')
        return JSONResponse(
            content={'error': 'Invalid request body.'}, status_code=400
        )

    # Extract custom headers from the request
    custom_headers = {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in STANDARD_HEADERS
    }

    # 2. Log the request.
    await _emit_debug_log(
        sid,
        'http-agent-card',
        'request',
        {
            'endpoint': '/agent-card',
            'payload': request_data,
            'custom_headers': custom_headers,
        },
    )

    # 3. Perform the main action and prepare response.
    try:
        async with httpx.AsyncClient(
            timeout=30.0, headers=custom_headers
        ) as client:
            card_resolver = get_card_resolver(client, agent_url)
            card = await card_resolver.get_agent_card()

        card_data = _get_agent_card_dict(card)
        validation_errors = validators.validate_agent_card(card_data)
        response_data = {
            'card': card_data,
            'validation_errors': validation_errors,
            # Endpoints and scopes for any OAuth2 scheme the card declares,
            # so the login form can be prefilled instead of typed out.
            'oauth_schemes': oauth.extract_oauth_schemes(card_data),
        }
        response_status = 200

    except httpx.RequestError as e:
        logger.error(
            f'Failed to connect to agent at {agent_url}', exc_info=True
        )
        response_data = {'error': f'Failed to connect to agent: {e}'}
        response_status = 502  # Bad Gateway
    except Exception as e:
        logger.error('An internal server error occurred', exc_info=True)
        response_data = {'error': f'An internal server error occurred: {e}'}
        response_status = 500

    # 4. Log the response and return it.
    await _emit_debug_log(
        sid,
        'http-agent-card',
        'response',
        {'status': response_status, 'payload': response_data},
    )
    return JSONResponse(content=response_data, status_code=response_status)


# ==============================================================================
# OAuth 2.0 Routes
# ==============================================================================


def _redirect_uri(request: Request) -> str:
    """Where the identity provider should send the user back to.

    This has to match what was registered with the provider byte for byte.
    Behind an ingress the request URL is useless for the purpose -- it shows
    the internal host and plain http -- so an explicit base URL wins, with
    the forwarding headers as a fallback for plain deployments.
    """
    configured = os.environ.get('OAUTH_REDIRECT_BASE_URL')
    if configured:
        return f'{configured.rstrip("/")}/oauth/callback'

    scheme = request.headers.get('x-forwarded-proto') or request.url.scheme
    host = request.headers.get('x-forwarded-host') or request.headers.get(
        'host'
    )
    return f'{scheme}://{host}/oauth/callback'


def _oauth_config_for(
    sid: str, payload: dict[str, Any]
) -> tuple[oauth.OAuthConfig, str]:
    """Build an OAuthConfig from the session's agent card plus user input.

    Endpoints come from the card so they cannot be typed wrong; identity and
    scopes come from the request.

    Returns:
        The config and the agent URL it belongs to, for the origin check.

    Raises:
        oauth.OAuthError: If the session or the named scheme is unknown.
    """
    if sid not in clients:
        raise oauth.OAuthError(
            'No active session for this connection. Connect to the agent '
            'first, then log in.'
        )

    _, _, card, _ = clients[sid]
    card_data = _get_agent_card_dict(card)
    schemes = oauth.extract_oauth_schemes(card_data)

    scheme_name = payload.get('scheme') or next(iter(schemes), None)
    if not scheme_name or scheme_name not in schemes:
        raise oauth.OAuthError(
            f"The agent card declares no OAuth2 scheme named '{scheme_name}'."
        )

    scheme = schemes[scheme_name]
    client_id = (payload.get('clientId') or '').strip()
    if not client_id:
        raise oauth.OAuthError('A client ID is required.')

    requested = payload.get('scopes')
    if isinstance(requested, str):
        scopes = tuple(requested.split())
    elif isinstance(requested, list):
        scopes = tuple(requested)
    else:
        scopes = tuple(scheme['requiredScopes'])

    config = oauth.OAuthConfig(
        scheme_name=scheme_name,
        token_url=scheme['tokenUrl'],
        client_id=client_id,
        authorization_url=scheme['authorizationUrl'],
        client_secret=(payload.get('clientSecret') or '').strip() or None,
        scopes=scopes,
        resource=scheme['resource'],
    )
    agent_url = scheme['resource'] or card_data.get('url') or ''
    return config, agent_url


def _foreign_host_response(
    config: oauth.OAuthConfig, agent_url: str, payload: dict[str, Any]
) -> JSONResponse | None:
    """Ask for confirmation before sending credentials off the agent's origin.

    The token endpoint is read out of an agent card, and the card came from
    a URL the user typed. A hostile card can therefore aim the endpoint at
    someone else's server and harvest whatever is sent. Nothing goes out
    until the user has seen the host and agreed to it.
    """
    if payload.get('confirmed') or not agent_url:
        return None

    foreign = oauth.foreign_endpoints(config, agent_url)
    if not foreign:
        return None

    return JSONResponse(
        content={
            'status': 'confirmation_required',
            'foreign_hosts': foreign,
            'agent_origin': oauth.origin_of(agent_url),
            'message': (
                'The OAuth endpoints declared by this agent card are hosted '
                'somewhere other than the agent itself. Your credentials '
                'would be sent there.'
            ),
        },
        status_code=409,
    )


@app.post('/oauth/start')
async def oauth_start(request: Request) -> JSONResponse:
    """Begin an interactive login and hand back the authorization URL."""
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            content={'error': 'Invalid request body.'}, status_code=400
        )

    sid = payload.get('sid')
    if not sid:
        return JSONResponse(
            content={'error': 'A session id is required.'}, status_code=400
        )

    try:
        config, agent_url = _oauth_config_for(sid, payload)
        blocked = _foreign_host_response(config, agent_url, payload)
        if blocked is not None:
            return blocked

        url, state = oauth_service.begin_authorization(
            sid, config, _redirect_uri(request)
        )
    except oauth.OAuthError as e:
        return JSONResponse(content={'error': str(e)}, status_code=400)

    await _emit_debug_log(
        sid,
        f'oauth-{state[:8]}',
        'request',
        {
            'endpoint': '/oauth/start',
            'scheme': config.scheme_name,
            'grant': oauth.GRANT_AUTHORIZATION_CODE,
            'scopes': list(config.scopes),
            'authorizationUrl': config.authorization_url,
        },
    )
    return JSONResponse(
        content={'status': 'ok', 'authorization_url': url, 'state': state}
    )


@app.post('/oauth/token-exchange')
async def oauth_token_exchange(request: Request) -> JSONResponse:
    """Exchange a token the user already holds for an agent-scoped one.

    RFC 8693. This is the path for authorization servers that do not offer
    an interactive login.
    """
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            content={'error': 'Invalid request body.'}, status_code=400
        )

    sid = payload.get('sid')
    subject_token = (payload.get('subjectToken') or '').strip()
    if not sid or not subject_token:
        return JSONResponse(
            content={'error': 'A session id and a subject token are required.'},
            status_code=400,
        )

    try:
        config, agent_url = _oauth_config_for(sid, payload)
        blocked = _foreign_host_response(config, agent_url, payload)
        if blocked is not None:
            return blocked

        await _emit_debug_log(
            sid,
            'oauth-token-exchange',
            'request',
            {
                'endpoint': config.token_url,
                'grant': oauth.GRANT_TOKEN_EXCHANGE,
                'scheme': config.scheme_name,
                'scopes': list(config.scopes),
                'resource': config.resource,
            },
        )
        token_set = await oauth_service.authorize_with_subject_token(
            sid, config, subject_token
        )
    except oauth.OAuthError as e:
        await _emit_oauth_status(sid, 'error', message=str(e))
        return JSONResponse(content={'error': str(e)}, status_code=400)

    await _emit_oauth_status(
        sid,
        'authorized',
        scheme=config.scheme_name,
        expires_at=token_set.expires_at,
    )
    return JSONResponse(
        content={
            'status': 'ok',
            'scheme': config.scheme_name,
            'expires_at': token_set.expires_at,
        }
    )


@app.get('/oauth/callback', response_class=HTMLResponse)
async def oauth_callback(request: Request) -> HTMLResponse:
    """Receive the redirect from the identity provider and store the token.

    Rendered into the popup the login was started in; the page reports the
    outcome and closes itself. The main window is updated over the socket,
    because it -- not this page -- holds the session.
    """
    params = request.query_params
    state = params.get('state') or ''
    error = params.get('error')

    if error:
        detail = params.get('error_description') or error
        session_id = oauth_service.session_for_state(state)
        if session_id:
            await _emit_oauth_status(session_id, 'error', message=detail)
        return _callback_page('Login failed', detail, ok=False)

    code = params.get('code')
    if not code or not state:
        return _callback_page(
            'Login failed',
            'The identity provider did not return a code.',
            ok=False,
        )

    try:
        result = await oauth_service.complete_authorization(state, code)
    except oauth.OAuthError as e:
        return _callback_page('Login failed', str(e), ok=False)

    await _emit_oauth_status(
        result.session_id,
        'authorized',
        scheme=result.scheme_name,
        expires_at=result.token_set.expires_at,
    )
    return _callback_page(
        'Signed in', 'You can close this window and return to the inspector.'
    )


async def _emit_oauth_status(sid: str, status: str, **fields: Any) -> None:
    """Tell the inspector window how a login went."""
    await sio.emit('oauth_status', {'status': status, **fields}, to=sid)


def _callback_page(title: str, detail: str, *, ok: bool = True) -> HTMLResponse:
    """A minimal self-closing page for the OAuth popup.

    Everything interpolated here originates from an external identity
    provider, so it is escaped rather than trusted.
    """
    colour = '#1a7f37' if ok else '#b42318'
    body = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{html.escape(title)}</title></head>
<body style="font-family:system-ui,sans-serif;padding:2rem;text-align:center">
  <h2 style="color:{colour}">{html.escape(title)}</h2>
  <p>{html.escape(detail)}</p>
  <script>setTimeout(function () {{ window.close(); }}, {1500 if ok else 6000});</script>
</body>
</html>"""
    return HTMLResponse(content=body, status_code=200 if ok else 400)


# ==============================================================================
# Socket.IO Event Handlers
# ==============================================================================


@sio.on('connect')
async def handle_connect(sid: str, environ: dict[str, Any]) -> None:
    """Handle the 'connect' socket.io event."""
    logger.info(f'Client connected: {sid}, environment: {environ}')


@sio.on('disconnect')
async def handle_disconnect(sid: str) -> None:
    """Handle the 'disconnect' socket.io event."""
    logger.info(f'Client disconnected: {sid}')
    oauth_service.purge(sid)
    if sid in clients:
        httpx_client, _, _, _ = clients.pop(sid)
        await httpx_client.aclose()
        logger.info(f'Cleaned up client for {sid}')


@sio.on('initialize_client')
async def handle_initialize_client(sid: str, data: dict[str, Any]) -> None:
    """Handle the 'initialize_client' socket.io event."""
    agent_card_url = data.get('url')

    custom_headers = data.get('customHeaders', {})

    if not agent_card_url:
        await sio.emit(
            'client_initialized',
            {'status': 'error', 'message': 'Agent URL is required.'},
            to=sid,
        )
        return

    httpx_client = None
    try:
        httpx_client = httpx.AsyncClient(timeout=600.0, headers=custom_headers)
        card_resolver = get_card_resolver(httpx_client, agent_card_url)
        card = await card_resolver.get_agent_card()

        a2a_config = _make_client_config()
        a2a_config.httpx_client = httpx_client  # type: ignore[attr-defined]

        factory = ClientFactory(a2a_config)
        # The interceptor reads the card's security schemes and asks
        # oauth_service for a matching token before every request. With no
        # token stored it returns None and the request is unchanged, so
        # this is inert until the user actually logs in.
        a2a_client = factory.create(card, [AuthInterceptor(oauth_service)])
        transport_protocol = _get_transport_from_card(card)

        clients[sid] = (httpx_client, a2a_client, card, transport_protocol)

        input_modes = _get_input_modes(card)
        output_modes = _get_output_modes(card)

        await sio.emit(
            'client_initialized',
            {
                'status': 'success',
                'transport': str(transport_protocol),
                'inputModes': input_modes,
                'outputModes': output_modes,
            },
            to=sid,
        )
    except Exception as e:
        logger.error(
            f'Failed to initialize client for {sid}: {e}', exc_info=True
        )
        # Clean up httpx_client
        if httpx_client is not None:
            await httpx_client.aclose()
        await sio.emit(
            'client_initialized', {'status': 'error', 'message': str(e)}, to=sid
        )


@sio.on('send_message')
async def handle_send_message(sid: str, json_data: dict[str, Any]) -> None:
    """Handle the 'send_message' socket.io event."""
    message_text = bleach.clean(json_data.get('message', ''))

    message_id = json_data.get('id', str(uuid4()))
    context_id = json_data.get('contextId')
    metadata = json_data.get('metadata', {})

    if sid not in clients:
        await sio.emit(
            'agent_response',
            {'error': 'Client not initialized.', 'id': message_id},
            to=sid,
        )
        return

    _, a2a_client, _, transport = clients[sid]

    attachments = json_data.get('attachments', [])

    parts: list[Any] = []
    if message_text:
        parts.append(_make_text_part(str(message_text)))

    for attachment in attachments:
        parts.append(
            _make_file_part(attachment['data'], attachment['mimeType'])
        )

    message = _make_message(
        role=_get_role_user(),
        parts=parts,
        message_id=message_id,
        context_id=context_id,
        metadata=metadata,
    )

    debug_request = {
        'transport': transport,
        'method': 'SendMessage',  # v1.0 PascalCase (was 'message/send' in v0.3)
        'message': _to_dict(message),
    }
    await _emit_debug_log(sid, message_id, 'request', debug_request)

    try:
        response_stream = await _send_message_compat(
            a2a_client,
            message,
            ClientCallContext(state={'sessionId': sid}),
        )
        async for stream_result in response_stream:
            await _process_a2a_response(stream_result, sid, message_id)

    except Exception as e:
        logger.error(f'Failed to send message for sid {sid}', exc_info=True)
        await sio.emit(
            'agent_response',
            {'error': f'Failed to send message: {e}', 'id': message_id},
            to=sid,
        )


# ==============================================================================
# Main Execution
# ==============================================================================


if __name__ == '__main__':
    import uvicorn

    # NOTE: The 'reload=True' flag is for development purposes only.
    # In a production environment, use a proper process manager like Gunicorn.
    uvicorn.run('app:app', host='127.0.0.1', port=5001, reload=True)
