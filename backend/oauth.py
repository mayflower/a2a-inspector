"""OAuth 2.0 client support for authenticating against A2A agents.

The A2A spec lets an AgentCard declare OAuth2 security schemes, and the
a2a-sdk ships an ``AuthInterceptor`` that applies a credential to outgoing
requests based on those schemes. What neither provides is a way to *obtain*
a token -- ``CredentialService.get_credentials`` is abstract. This module
fills that gap.

Two grant types are supported:

- ``authorization_code`` with PKCE (RFC 7636), where the user logs in at the
  agent's identity provider. This is the interactive flow.
- ``urn:ietf:params:oauth:grant-type:token-exchange`` (RFC 8693), where a
  token the caller already holds is exchanged for one scoped to the agent.

Tokens are cached per (session, scheme) and refreshed on demand. Because
``get_credentials`` runs before every request, a short-lived access token
never has to be re-entered by hand.

Nothing here imports FastAPI or Socket.IO so the module stays testable on
its own; ``app.py`` owns the HTTP routes and the session plumbing.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlparse

import httpx

from a2a.client.auth.credentials import CredentialService


if TYPE_CHECKING:
    from a2a.client.client import ClientCallContext


logger = logging.getLogger(__name__)

GRANT_AUTHORIZATION_CODE = 'authorization_code'
GRANT_REFRESH_TOKEN = 'refresh_token'
GRANT_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'

TOKEN_TYPE_ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token'

# Refresh this many seconds before the token actually expires, so a request
# in flight cannot be rejected for an expiry that passed mid-roundtrip.
EXPIRY_MARGIN_SECONDS = 30.0

# How long an unfinished authorization may sit around waiting for the user
# to come back from the identity provider.
PENDING_TTL_SECONDS = 600.0

# Default when the token response omits expires_in.
DEFAULT_EXPIRES_IN_SECONDS = 300.0

# Discovery documents change rarely, but this is a debugging tool and people
# do edit their own authorization servers while it is open, so the cache is
# short rather than permanent.
METADATA_TTL_SECONDS = 300.0

_HTTP_OK = 200
_HTTP_BAD_REQUEST = 400


class OAuthError(Exception):
    """Raised when an OAuth operation fails in a way the user must see."""


# ==============================================================================
# Data model
# ==============================================================================


@dataclass(frozen=True)
class OAuthConfig:
    """Everything needed to obtain a token for one security scheme.

    Endpoints come from the AgentCard; the client identity comes from the
    user, because the inspector is not a registered client of any agent it
    might be pointed at.
    """

    scheme_name: str
    token_url: str
    client_id: str
    authorization_url: str | None = None
    client_secret: str | None = None
    scopes: tuple[str, ...] = ()
    resource: str | None = None

    @property
    def scope_string(self) -> str:
        """Scopes joined for use as an OAuth ``scope`` parameter."""
        return ' '.join(self.scopes)


@dataclass
class TokenSet:
    """An access token plus what is needed to renew it."""

    access_token: str
    refresh_token: str | None = None
    expires_at: float = 0.0

    def is_usable(self, *, now: float | None = None) -> bool:
        """Whether the token can still be used without renewing it first."""
        current = time.time() if now is None else now
        return self.expires_at - current > EXPIRY_MARGIN_SECONDS


@dataclass(frozen=True)
class AuthorizationResult:
    """What a completed interactive login produced."""

    session_id: str
    scheme_name: str
    token_set: TokenSet


@dataclass
class PendingAuthorization:
    """An authorization_code flow that is waiting for the user to return."""

    session_id: str
    config: OAuthConfig
    code_verifier: str
    redirect_uri: str
    created_at: float = field(default_factory=time.time)

    def is_expired(self, *, now: float | None = None) -> bool:
        """Whether this authorization sat unfinished for too long."""
        current = time.time() if now is None else now
        return current - self.created_at > PENDING_TTL_SECONDS


# ==============================================================================
# Agent card parsing
# ==============================================================================


def _oauth2_scheme_body(scheme: Any) -> dict[str, Any] | None:
    """Return the OAuth2 body of a security scheme, or None if it is not one.

    Handles both card formats: v1.0 nests the scheme under a
    ``oauth2SecurityScheme`` key, while v0.3 marks it with ``type: oauth2``.
    """
    if not isinstance(scheme, dict):
        return None
    nested = scheme.get('oauth2SecurityScheme')
    if isinstance(nested, dict):
        return nested
    if scheme.get('type') == 'oauth2':
        return scheme
    return None


def _required_scopes(card: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """Map each required security scheme to the scopes the card asks for.

    v1.0 uses ``securityRequirements: [{schemes: {Name: {list: [...]}}}]``,
    v0.3 uses ``security: [{Name: [...]}]``.
    """
    result: dict[str, tuple[str, ...]] = {}

    for requirement in card.get('securityRequirements') or []:
        schemes = (requirement or {}).get('schemes') or {}
        for name, value in schemes.items():
            scopes = (value or {}).get('list') or []
            result[name] = tuple(scopes)

    for requirement in card.get('security') or []:
        for name, scopes in (requirement or {}).items():
            if name not in result:
                result[name] = tuple(scopes or [])

    return result


def _agent_resource(card: dict[str, Any]) -> str | None:
    """The agent's own URL, used as the RFC 8707 ``resource`` parameter."""
    interfaces = card.get('supportedInterfaces') or []
    if interfaces:
        url = (interfaces[0] or {}).get('url')
        if url:
            return str(url)
    url = card.get('url')
    return str(url) if url else None


def extract_oauth_schemes(card: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Pull the OAuth2 security schemes out of an agent card.

    Args:
        card: The agent card as a dict (either protocol version).

    Returns:
        A mapping of scheme name to a descriptor with the endpoints, the
        scopes the card requires, and whether the scheme is actually
        required. Descriptors are plain dicts so they can be sent to the
        browser as JSON to prefill the login form.
    """
    schemes = card.get('securitySchemes') or {}
    if not isinstance(schemes, dict):
        return {}

    required = _required_scopes(card)
    resource = _agent_resource(card)
    result: dict[str, dict[str, Any]] = {}

    for name, scheme in schemes.items():
        body = _oauth2_scheme_body(scheme)
        if body is None:
            continue

        flows = body.get('flows') or {}
        auth_code = flows.get('authorizationCode') or {}
        client_creds = flows.get('clientCredentials') or {}

        token_url = auth_code.get('tokenUrl') or client_creds.get('tokenUrl')
        if not token_url:
            # Without a token endpoint there is nothing we can drive.
            continue

        # Offer the card's declared scopes, but prefer the ones the card
        # actually requires for this scheme.
        declared = tuple((auth_code.get('scopes') or {}).keys()) or tuple(
            (client_creds.get('scopes') or {}).keys()
        )

        result[name] = {
            'schemeName': name,
            'authorizationUrl': auth_code.get('authorizationUrl'),
            'tokenUrl': token_url,
            'availableScopes': list(declared),
            'requiredScopes': list(required.get(name, ())),
            'required': name in required,
            'metadataUrl': body.get('oauth2MetadataUrl'),
            'resource': resource,
            'description': body.get('description'),
        }

    return result


# ==============================================================================
# Origin checking
# ==============================================================================


def origin_of(url: str) -> str:
    """Normalized scheme://host:port of a URL, with default ports dropped."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or '').lower()
    host = (parsed.hostname or '').lower()
    port = parsed.port
    if port is None or (scheme, port) in {('http', 80), ('https', 443)}:
        return f'{scheme}://{host}'
    return f'{scheme}://{host}:{port}'


def is_same_origin(a: str, b: str) -> bool:
    """Whether two URLs share a scheme, host and port."""
    return origin_of(a) == origin_of(b)


def foreign_endpoints(config: OAuthConfig, agent_url: str) -> list[str]:
    """OAuth endpoints that do not live on the agent's own origin.

    The token URL is taken from an agent card, and the card comes from a
    URL the user supplied. A hostile card could therefore point the token
    endpoint at an attacker and collect whatever credentials are sent. The
    caller is expected to surface this list and get confirmation before
    any request goes out.
    """
    candidates = [config.token_url]
    if config.authorization_url:
        candidates.append(config.authorization_url)

    foreign = []
    for url in candidates:
        if not is_same_origin(url, agent_url):
            host = origin_of(url)
            if host not in foreign:
                foreign.append(host)
    return foreign


# ==============================================================================
# PKCE
# ==============================================================================


def _b64url(raw: bytes) -> str:
    """Base64url without padding, as RFC 7636 requires."""
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def generate_code_verifier() -> str:
    """A fresh PKCE code verifier (43 characters, the RFC 7636 minimum)."""
    return _b64url(secrets.token_bytes(32))


def code_challenge_for(verifier: str) -> str:
    """The S256 challenge derived from a code verifier."""
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return _b64url(digest)


def generate_state() -> str:
    """An unguessable value binding a callback to the session that began it."""
    return secrets.token_urlsafe(32)


def build_authorization_url(
    config: OAuthConfig,
    redirect_uri: str,
    state: str,
    code_verifier: str,
) -> str:
    """Build the URL the user is sent to in order to log in.

    Args:
        config: The scheme to authorize against.
        redirect_uri: Where the provider sends the user back to. Must match
            what was registered with the provider exactly.
        state: CSRF value tying the callback to this session.
        code_verifier: The PKCE verifier; only its challenge is sent.

    Returns:
        The absolute authorization URL.

    Raises:
        OAuthError: If the scheme declares no authorization endpoint.
    """
    if not config.authorization_url:
        raise OAuthError(
            f"Security scheme '{config.scheme_name}' declares no "
            'authorization endpoint, so an interactive login is not '
            'possible. Use token exchange instead.'
        )

    params = {
        'response_type': 'code',
        'client_id': config.client_id,
        'redirect_uri': redirect_uri,
        'state': state,
        'code_challenge': code_challenge_for(code_verifier),
        'code_challenge_method': 'S256',
    }
    if config.scopes:
        params['scope'] = config.scope_string
    if config.resource:
        params['resource'] = config.resource

    separator = '&' if urlparse(config.authorization_url).query else '?'
    return f'{config.authorization_url}{separator}{urlencode(params)}'


# ==============================================================================
# Token endpoint
# ==============================================================================


def _parse_token_response(payload: dict[str, Any]) -> TokenSet:
    """Turn a token endpoint response body into a TokenSet."""
    access_token = payload.get('access_token')
    if not access_token:
        raise OAuthError(
            'Token endpoint returned no access_token '
            f'(keys: {sorted(payload)}).'
        )

    try:
        expires_in = float(
            payload.get('expires_in') or DEFAULT_EXPIRES_IN_SECONDS
        )
    except (TypeError, ValueError):
        expires_in = DEFAULT_EXPIRES_IN_SECONDS

    return TokenSet(
        access_token=str(access_token),
        refresh_token=payload.get('refresh_token'),
        expires_at=time.time() + expires_in,
    )


async def _post_token_request(
    config: OAuthConfig,
    data: dict[str, str],
    http: httpx.AsyncClient,
) -> TokenSet:
    """POST a grant to the token endpoint and parse the result.

    A confidential client authenticates with HTTP Basic
    (``client_secret_basic``); a public client sends its ``client_id`` in
    the body, which is the recommended shape for PKCE flows.
    """
    # httpx exports the USE_CLIENT_DEFAULT sentinel but not its type, so
    # the auth argument is assembled as a kwarg rather than a typed union.
    request_kwargs: dict[str, Any] = {'data': data}
    if config.client_secret:
        request_kwargs['auth'] = (config.client_id, config.client_secret)
    else:
        request_kwargs['data'] = {**data, 'client_id': config.client_id}

    try:
        response = await http.post(config.token_url, **request_kwargs)
    except httpx.RequestError as e:
        raise OAuthError(
            f'Could not reach the token endpoint {config.token_url}: {e}'
        ) from e

    if response.status_code >= _HTTP_BAD_REQUEST:
        raise OAuthError(_describe_token_error(response))

    try:
        payload = response.json()
    except ValueError as e:
        raise OAuthError(
            'Token endpoint returned a body that is not JSON.'
        ) from e

    return _parse_token_response(payload)


def _describe_token_error(response: httpx.Response) -> str:
    """Build a message from an RFC 6749 error response, falling back to text."""
    try:
        payload = response.json()
    except ValueError:
        payload = {}

    if isinstance(payload, dict) and payload.get('error'):
        detail = payload.get('error_description') or ''
        suffix = f': {detail}' if detail else ''
        return (
            f'Token request failed ({response.status_code}) '
            f'{payload["error"]}{suffix}'
        )

    return (
        f'Token request failed ({response.status_code}): {response.text[:200]}'
    )


async def exchange_code(
    config: OAuthConfig,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    http: httpx.AsyncClient,
) -> TokenSet:
    """Trade an authorization code for tokens."""
    data = {
        'grant_type': GRANT_AUTHORIZATION_CODE,
        'code': code,
        'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,
    }
    if config.resource:
        data['resource'] = config.resource
    return await _post_token_request(config, data, http)


async def exchange_subject_token(
    config: OAuthConfig,
    subject_token: str,
    http: httpx.AsyncClient,
    subject_token_type: str = TOKEN_TYPE_ACCESS_TOKEN,
) -> TokenSet:
    """Exchange a token the caller already holds for an agent-scoped one.

    RFC 8693. Used where the agent's authorization server does not offer an
    interactive login and instead trusts tokens from an upstream issuer.
    """
    data = {
        'grant_type': GRANT_TOKEN_EXCHANGE,
        'subject_token': subject_token,
        'subject_token_type': subject_token_type,
    }
    if config.scopes:
        data['scope'] = config.scope_string
    if config.resource:
        data['resource'] = config.resource
    return await _post_token_request(config, data, http)


async def refresh_tokens(
    config: OAuthConfig,
    token_set: TokenSet,
    http: httpx.AsyncClient,
) -> TokenSet:
    """Renew an expiring access token.

    Providers may omit a new refresh token, in which case the existing one
    stays valid and is carried over.
    """
    if not token_set.refresh_token:
        raise OAuthError('No refresh token available for this session.')

    data = {
        'grant_type': GRANT_REFRESH_TOKEN,
        'refresh_token': token_set.refresh_token,
    }
    if config.scopes:
        data['scope'] = config.scope_string

    renewed = await _post_token_request(config, data, http)
    if not renewed.refresh_token:
        renewed.refresh_token = token_set.refresh_token
    return renewed


# ==============================================================================
# Authorization server discovery (RFC 8414) and client registration (RFC 7591)
# ==============================================================================


def well_known_urls(scheme: dict[str, Any]) -> list[str]:
    """Candidate metadata URLs for a security scheme, best first.

    The card may name one outright. Otherwise RFC 8414 says to insert
    ``/.well-known/oauth-authorization-server`` after the issuer's host,
    but plenty of servers put it after the issuer's path instead, so both
    are tried before giving up.
    """
    candidates: list[str] = []
    declared = scheme.get('metadataUrl')
    if declared:
        candidates.append(str(declared))

    base = scheme.get('authorizationUrl') or scheme.get('tokenUrl')
    if base:
        parsed = urlparse(str(base))
        origin = origin_of(str(base))
        # Strip the last path segment: .../oauth/token -> /oauth
        issuer_path = parsed.path.rsplit('/', 1)[0].rstrip('/')
        for suffix in (
            # RFC 8414 to the letter: the well-known segment goes between
            # host and issuer path.
            f'{origin}/.well-known/oauth-authorization-server{issuer_path}',
            # Common deviation: appended to the issuer path instead.
            f'{origin}{issuer_path}/.well-known/oauth-authorization-server',
            # Also common: served at the host root even though the issuer
            # carries a path. Observed on a real deployment.
            f'{origin}/.well-known/oauth-authorization-server',
            f'{origin}/.well-known/openid-configuration',
        ):
            if suffix not in candidates:
                candidates.append(suffix)

    return candidates


_metadata_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_registration_cache: dict[tuple[str, str], tuple[str, str | None]] = {}


def clear_discovery_caches() -> None:
    """Drop cached metadata and registrations (used by tests)."""
    _metadata_cache.clear()
    _registration_cache.clear()


async def fetch_metadata(
    scheme: dict[str, Any], http: httpx.AsyncClient
) -> dict[str, Any]:
    """Fetch an authorization server's metadata document.

    Best effort by design: discovery only ever adds information, so any
    failure returns an empty dict and the card's own declarations stand.
    """
    candidates = well_known_urls(scheme)
    cache_key = candidates[0] if candidates else ''
    cached = _metadata_cache.get(cache_key)
    if cached and time.time() - cached[0] < METADATA_TTL_SECONDS:
        return cached[1]

    for url in candidates:
        try:
            response = await http.get(url, timeout=10.0)
        except httpx.RequestError:
            continue
        if response.status_code != _HTTP_OK:
            continue
        try:
            payload = response.json()
        except ValueError:
            continue
        if isinstance(payload, dict) and payload.get('issuer'):
            logger.info('Discovered authorization server metadata at %s', url)
            _metadata_cache[cache_key] = (time.time(), payload)
            return payload

    _metadata_cache[cache_key] = (time.time(), {})
    return {}


async def describe_scheme(
    scheme: dict[str, Any], http: httpx.AsyncClient
) -> dict[str, Any]:
    """Enrich a card-derived scheme with what the server actually supports.

    Agent cards are written by hand and drift: one observed card advertises
    an authorization_code flow against a server whose metadata lists only
    token-exchange. Where the two disagree the server wins, so the UI can
    offer the grants that will actually work instead of the ones that were
    promised.
    """
    metadata = await fetch_metadata(scheme, http)
    enriched = dict(scheme)
    enriched['discovered'] = bool(metadata)

    if metadata:
        # The server's own endpoints supersede the card's.
        if metadata.get('authorization_endpoint'):
            enriched['authorizationUrl'] = metadata['authorization_endpoint']
        if metadata.get('token_endpoint'):
            enriched['tokenUrl'] = metadata['token_endpoint']
        if metadata.get('scopes_supported'):
            enriched['availableScopes'] = list(metadata['scopes_supported'])
        enriched['registrationEndpoint'] = metadata.get('registration_endpoint')
        enriched['issuer'] = metadata.get('issuer')

    grants = metadata.get('grant_types_supported')
    if grants:
        enriched['grantTypesSupported'] = list(grants)
        enriched['supportsAuthorizationCode'] = (
            GRANT_AUTHORIZATION_CODE in grants
            and bool(enriched.get('authorizationUrl'))
        )
        enriched['supportsTokenExchange'] = GRANT_TOKEN_EXCHANGE in grants
    else:
        # Without metadata, fall back to what the card implies.
        enriched['grantTypesSupported'] = []
        enriched['supportsAuthorizationCode'] = bool(
            enriched.get('authorizationUrl')
        )
        enriched['supportsTokenExchange'] = True

    enriched.setdefault('registrationEndpoint', None)
    enriched['supportsDynamicRegistration'] = bool(
        enriched.get('registrationEndpoint')
    )
    return enriched


async def register_client(
    registration_endpoint: str,
    redirect_uri: str,
    scopes: tuple[str, ...],
    http: httpx.AsyncClient,
    client_name: str = 'A2A Inspector',
) -> tuple[str, str | None]:
    """Register this inspector as a client, so nobody has to do it by hand.

    RFC 7591. Servers that support this hand back a client_id on the spot,
    which removes the one piece of setup a user would otherwise have to
    arrange out of band.

    Returns:
        The issued client id and secret; the secret is None for a public
        client, which is what we ask for.

    Raises:
        OAuthError: If registration is rejected or malformed.
    """
    cache_key = (registration_endpoint, redirect_uri)
    cached = _registration_cache.get(cache_key)
    if cached:
        return cached

    body: dict[str, Any] = {
        'client_name': client_name,
        'redirect_uris': [redirect_uri],
        'grant_types': [GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN],
        'response_types': ['code'],
        # Public client: PKCE carries the security, no secret to store.
        'token_endpoint_auth_method': 'none',
        'application_type': 'web',
    }
    if scopes:
        body['scope'] = ' '.join(scopes)

    try:
        response = await http.post(
            registration_endpoint, json=body, timeout=15.0
        )
    except httpx.RequestError as e:
        raise OAuthError(
            f'Could not reach the registration endpoint '
            f'{registration_endpoint}: {e}'
        ) from e

    if response.status_code >= _HTTP_BAD_REQUEST:
        raise OAuthError(_describe_token_error(response))

    try:
        payload = response.json()
    except ValueError as e:
        raise OAuthError(
            'Registration endpoint returned a body that is not JSON.'
        ) from e

    client_id = payload.get('client_id')
    if not client_id:
        raise OAuthError('Registration succeeded but returned no client_id.')

    logger.info(
        'Registered dynamically at %s as client %s',
        registration_endpoint,
        client_id,
    )
    issued = (str(client_id), payload.get('client_secret'))
    _registration_cache[cache_key] = issued
    return issued


# ==============================================================================
# Credential service
# ==============================================================================


class OAuthCredentialService(CredentialService):
    """Supplies tokens to the SDK's AuthInterceptor, renewing as needed.

    The SDK calls ``get_credentials`` before every request, which is what
    makes short token lifetimes a non-issue: a token nearing expiry is
    refreshed transparently rather than surfacing to the user.

    State is keyed by Socket.IO session id, matching how ``app.py`` scopes
    the rest of its per-connection state.
    """

    def __init__(self, http: httpx.AsyncClient | None = None) -> None:
        self._tokens: dict[tuple[str, str], TokenSet] = {}
        self._configs: dict[tuple[str, str], OAuthConfig] = {}
        self._pending: dict[str, PendingAuthorization] = {}
        self._owns_http = http is None
        # A dedicated client: the per-session one in app.py carries the
        # user's custom headers, which have no business going to an
        # identity provider.
        self._http = http or httpx.AsyncClient(timeout=30.0)

    # -- authorization_code ------------------------------------------------

    def begin_authorization(
        self,
        session_id: str,
        config: OAuthConfig,
        redirect_uri: str,
    ) -> tuple[str, str]:
        """Start an interactive login.

        Returns:
            A tuple of (authorization_url, state).
        """
        self._expire_pending()
        state = generate_state()
        verifier = generate_code_verifier()
        self._pending[state] = PendingAuthorization(
            session_id=session_id,
            config=config,
            code_verifier=verifier,
            redirect_uri=redirect_uri,
        )
        url = build_authorization_url(config, redirect_uri, state, verifier)
        return url, state

    def session_for_state(self, state: str) -> str | None:
        """The session a pending authorization belongs to, without consuming it.

        Used to route a provider-side error back to the right window.
        """
        pending = self._pending.get(state)
        return pending.session_id if pending else None

    async def complete_authorization(
        self, state: str, code: str
    ) -> AuthorizationResult:
        """Finish an interactive login and store the resulting token.

        Args:
            state: The value handed back by the identity provider.
            code: The authorization code to redeem.

        Returns:
            The session, scheme and token the login produced.

        Raises:
            OAuthError: If the state is unknown or too old. Both cases are
                treated identically so a caller cannot probe for valid
                states.
        """
        self._expire_pending()
        pending = self._pending.pop(state, None)
        if pending is None:
            raise OAuthError(
                'This login could not be matched to an open session. It may '
                'have expired -- start the login again.'
            )

        token_set = await exchange_code(
            pending.config,
            code,
            pending.code_verifier,
            pending.redirect_uri,
            self._http,
        )
        self.store(pending.session_id, pending.config, token_set)
        return AuthorizationResult(
            session_id=pending.session_id,
            scheme_name=pending.config.scheme_name,
            token_set=token_set,
        )

    def _expire_pending(self, *, now: float | None = None) -> None:
        """Drop authorizations the user never came back from."""
        stale = [
            state
            for state, pending in self._pending.items()
            if pending.is_expired(now=now)
        ]
        for state in stale:
            del self._pending[state]

    # -- token-exchange ----------------------------------------------------

    async def authorize_with_subject_token(
        self,
        session_id: str,
        config: OAuthConfig,
        subject_token: str,
    ) -> TokenSet:
        """Obtain a token by exchanging one the caller already holds."""
        token_set = await exchange_subject_token(
            config, subject_token, self._http
        )
        self.store(session_id, config, token_set)
        return token_set

    # -- storage -----------------------------------------------------------

    def store(
        self, session_id: str, config: OAuthConfig, token_set: TokenSet
    ) -> None:
        """Remember a token and the config needed to renew it."""
        key = (session_id, config.scheme_name)
        self._configs[key] = config
        self._tokens[key] = token_set

    def token_for(self, session_id: str, scheme_name: str) -> TokenSet | None:
        """The stored token for a session and scheme, if any."""
        return self._tokens.get((session_id, scheme_name))

    def purge(self, session_id: str) -> None:
        """Forget everything belonging to a session.

        Called on disconnect. Also clears any authorization that session
        started but never completed.
        """
        for key in [k for k in self._tokens if k[0] == session_id]:
            del self._tokens[key]
        for key in [k for k in self._configs if k[0] == session_id]:
            del self._configs[key]
        for state in [
            s
            for s, pending in self._pending.items()
            if pending.session_id == session_id
        ]:
            del self._pending[state]

    async def aclose(self) -> None:
        """Release the HTTP client, if this service created it."""
        if self._owns_http:
            await self._http.aclose()

    # -- CredentialService -------------------------------------------------

    async def get_credentials(
        self,
        security_scheme_name: str,
        context: ClientCallContext | None,
    ) -> str | None:
        """Return a usable access token, refreshing it if it is about to die.

        Returns None rather than raising when nothing is stored: an agent
        may declare a scheme the user chose not to authenticate against,
        and the request should be allowed to proceed and fail on its own
        terms.
        """
        session_id = None
        if context is not None and context.state:
            session_id = context.state.get('sessionId')
        if not session_id:
            return None

        key = (session_id, security_scheme_name)
        token_set = self._tokens.get(key)
        if token_set is None:
            return None

        if token_set.is_usable():
            return token_set.access_token

        config = self._configs.get(key)
        if config is None or not token_set.refresh_token:
            # Expired with no way to renew. Hand it over anyway: a clear
            # 401 from the agent beats a silently unauthenticated request.
            return token_set.access_token

        try:
            renewed = await refresh_tokens(config, token_set, self._http)
        except OAuthError:
            logger.warning(
                'Refreshing the token for scheme %s failed; using the '
                'expiring one.',
                security_scheme_name,
                exc_info=True,
            )
            return token_set.access_token

        self._tokens[key] = renewed
        logger.info(
            'Refreshed access token for scheme %s.', security_scheme_name
        )
        return renewed.access_token
