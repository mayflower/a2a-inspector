"""Tests for the OAuth 2.0 client support in backend/oauth.py."""

import base64
import hashlib
import time

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from a2a.client.client import ClientCallContext

from backend import oauth


TOKEN_URL = 'https://agent.example/oauth/token'
AUTHORIZE_URL = 'https://agent.example/oauth/authorize'
AGENT_URL = 'https://agent.example/a2a/demo'
REDIRECT_URI = 'https://inspector.example/oauth/callback'


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def config():
    """A public client (PKCE, no secret) -- the recommended default."""
    return oauth.OAuthConfig(
        scheme_name='AgentOAuth',
        token_url=TOKEN_URL,
        client_id='inspector',
        authorization_url=AUTHORIZE_URL,
        scopes=('a2a:message:send',),
        resource=AGENT_URL,
    )


@pytest.fixture
def confidential_config(config):
    """The same client, but with a secret to authenticate with."""
    return oauth.OAuthConfig(
        scheme_name=config.scheme_name,
        token_url=config.token_url,
        client_id=config.client_id,
        authorization_url=config.authorization_url,
        client_secret='s3cret',
        scopes=config.scopes,
        resource=config.resource,
    )


@pytest.fixture
def card_v10():
    """A v1.0 agent card modelled on a real OAuth-protected agent."""
    return {
        'name': 'demo_agent',
        'supportedInterfaces': [
            {'url': AGENT_URL, 'protocolBinding': 'JSONRPC'}
        ],
        'securitySchemes': {
            'AgentOAuth': {
                'oauth2SecurityScheme': {
                    'description': 'Agent OAuth',
                    'flows': {
                        'authorizationCode': {
                            'authorizationUrl': AUTHORIZE_URL,
                            'tokenUrl': TOKEN_URL,
                            'scopes': {
                                'a2a:message:send': 'Send messages.',
                                'a2a:task:read': 'Read tasks.',
                            },
                            'pkceRequired': True,
                        }
                    },
                    'oauth2MetadataUrl': (
                        'https://agent.example/.well-known/'
                        'oauth-authorization-server'
                    ),
                }
            },
            'BearerAuth': {
                'httpAuthSecurityScheme': {'scheme': 'bearer'},
            },
        },
        'securityRequirements': [
            {'schemes': {'AgentOAuth': {'list': ['a2a:message:send']}}}
        ],
    }


@pytest.fixture
def card_v03():
    """A v0.3 agent card: top-level url, flat scheme, `security` key."""
    return {
        'name': 'legacy_agent',
        'url': AGENT_URL,
        'securitySchemes': {
            'AgentOAuth': {
                'type': 'oauth2',
                'flows': {
                    'authorizationCode': {
                        'authorizationUrl': AUTHORIZE_URL,
                        'tokenUrl': TOKEN_URL,
                        'scopes': {'a2a:message:send': 'Send messages.'},
                    }
                },
            }
        },
        'security': [{'AgentOAuth': ['a2a:message:send']}],
    }


def _context(session_id='sid-1'):
    return ClientCallContext(state={'sessionId': session_id})


def _token_response(
    access: str = 'access-1',
    refresh: str | None = 'refresh-1',
    expires_in: int = 300,
    **extra,
):
    payload = {
        'access_token': access,
        'token_type': 'Bearer',
        'expires_in': expires_in,
        **extra,
    }
    if refresh is not None:
        payload['refresh_token'] = refresh
    return httpx.Response(200, json=payload)


# ==============================================================================
# Agent card parsing
# ==============================================================================


class TestExtractOAuthSchemes:
    def test_v10_card(self, card_v10):
        """A v1.0 card exposes its oauth2 scheme with endpoints and scopes."""
        schemes = oauth.extract_oauth_schemes(card_v10)

        assert set(schemes) == {'AgentOAuth'}
        scheme = schemes['AgentOAuth']
        assert scheme['tokenUrl'] == TOKEN_URL
        assert scheme['authorizationUrl'] == AUTHORIZE_URL
        assert scheme['requiredScopes'] == ['a2a:message:send']
        assert scheme['required'] is True
        assert scheme['resource'] == AGENT_URL
        assert sorted(scheme['availableScopes']) == [
            'a2a:message:send',
            'a2a:task:read',
        ]

    def test_v03_card(self, card_v03):
        """A v0.3 card uses `type: oauth2` and `security`, and still parses."""
        schemes = oauth.extract_oauth_schemes(card_v03)

        assert set(schemes) == {'AgentOAuth'}
        assert schemes['AgentOAuth']['requiredScopes'] == ['a2a:message:send']
        assert schemes['AgentOAuth']['resource'] == AGENT_URL

    def test_non_oauth_schemes_are_ignored(self, card_v10):
        """Bearer and API-key schemes are not OAuth and must not appear."""
        assert 'BearerAuth' not in oauth.extract_oauth_schemes(card_v10)

    def test_scheme_without_token_url_is_skipped(self, card_v10):
        """Without a token endpoint there is no flow we could drive."""
        del card_v10['securitySchemes']['AgentOAuth']['oauth2SecurityScheme'][
            'flows'
        ]['authorizationCode']['tokenUrl']

        assert oauth.extract_oauth_schemes(card_v10) == {}

    def test_declared_but_not_required(self, card_v10):
        """A scheme the card declares but does not demand is marked so."""
        del card_v10['securityRequirements']

        assert (
            oauth.extract_oauth_schemes(card_v10)['AgentOAuth']['required']
            is False
        )

    @pytest.mark.parametrize('card', [{}, {'securitySchemes': None}])
    def test_cards_without_schemes(self, card):
        """Cards with no security section yield nothing rather than raising."""
        assert oauth.extract_oauth_schemes(card) == {}


# ==============================================================================
# Origin checks
# ==============================================================================


class TestOriginChecks:
    @pytest.mark.parametrize(
        ('a', 'b'),
        [
            ('https://h.example/a', 'https://h.example/b'),
            ('https://h.example:443/a', 'https://h.example/b'),
            ('http://h.example:80/a', 'http://h.example/b'),
            ('https://H.example/a', 'https://h.example/b'),
        ],
    )
    def test_same_origin(self, a, b):
        assert oauth.is_same_origin(a, b)

    @pytest.mark.parametrize(
        ('a', 'b'),
        [
            ('https://h.example/a', 'https://other.example/b'),
            ('https://h.example/a', 'http://h.example/b'),
            ('https://h.example:8443/a', 'https://h.example/b'),
        ],
    )
    def test_different_origin(self, a, b):
        assert not oauth.is_same_origin(a, b)

    def test_foreign_endpoints_empty_for_own_origin(self, config):
        assert oauth.foreign_endpoints(config, AGENT_URL) == []

    def test_foreign_token_endpoint_is_reported(self, config):
        """A card pointing the token endpoint elsewhere must be flagged."""
        hostile = oauth.OAuthConfig(
            scheme_name=config.scheme_name,
            token_url='https://evil.example/token',
            client_id=config.client_id,
            authorization_url=config.authorization_url,
        )

        assert oauth.foreign_endpoints(hostile, AGENT_URL) == [
            'https://evil.example'
        ]

    def test_each_foreign_host_reported_once(self, config):
        """Both endpoints on the same foreign host collapse to one entry."""
        hostile = oauth.OAuthConfig(
            scheme_name=config.scheme_name,
            token_url='https://evil.example/token',
            client_id=config.client_id,
            authorization_url='https://evil.example/authorize',
        )

        assert oauth.foreign_endpoints(hostile, AGENT_URL) == [
            'https://evil.example'
        ]


# ==============================================================================
# PKCE and the authorization URL
# ==============================================================================


class TestPkce:
    def test_verifier_meets_rfc7636_length(self):
        """RFC 7636 requires 43-128 characters."""
        verifier = oauth.generate_code_verifier()

        assert 43 <= len(verifier) <= 128

    def test_verifiers_are_unique(self):
        verifiers = {oauth.generate_code_verifier() for _ in range(50)}

        assert len(verifiers) == 50

    def test_challenge_is_unpadded_s256(self):
        """The challenge is base64url(sha256(verifier)) without padding."""
        verifier = oauth.generate_code_verifier()
        expected = (
            base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode('ascii')).digest()
            )
            .decode('ascii')
            .rstrip('=')
        )

        challenge = oauth.code_challenge_for(verifier)

        assert challenge == expected
        assert '=' not in challenge


class TestAuthorizationUrl:
    def test_contains_required_parameters(self, config):
        verifier = oauth.generate_code_verifier()

        url = oauth.build_authorization_url(
            config, REDIRECT_URI, 'state-1', verifier
        )

        params = parse_qs(urlparse(url).query)
        assert params['response_type'] == ['code']
        assert params['client_id'] == ['inspector']
        assert params['redirect_uri'] == [REDIRECT_URI]
        assert params['state'] == ['state-1']
        assert params['code_challenge_method'] == ['S256']
        assert params['code_challenge'] == [oauth.code_challenge_for(verifier)]
        assert params['scope'] == ['a2a:message:send']
        assert params['resource'] == [AGENT_URL]

    def test_never_leaks_the_verifier(self, config):
        """Only the challenge may travel to the browser."""
        verifier = oauth.generate_code_verifier()

        url = oauth.build_authorization_url(
            config, REDIRECT_URI, 'state-1', verifier
        )

        assert verifier not in url

    def test_preserves_an_existing_query_string(self, config):
        with_query = oauth.OAuthConfig(
            scheme_name=config.scheme_name,
            token_url=config.token_url,
            client_id=config.client_id,
            authorization_url=f'{AUTHORIZE_URL}?tenant=acme',
        )

        url = oauth.build_authorization_url(
            with_query, REDIRECT_URI, 'state-1', 'verifier'
        )

        assert parse_qs(urlparse(url).query)['tenant'] == ['acme']

    def test_without_authorization_endpoint(self, config):
        """A token-exchange-only server cannot do an interactive login."""
        exchange_only = oauth.OAuthConfig(
            scheme_name=config.scheme_name,
            token_url=config.token_url,
            client_id=config.client_id,
        )

        with pytest.raises(oauth.OAuthError, match='no.*authorization'):
            oauth.build_authorization_url(
                exchange_only, REDIRECT_URI, 'state-1', 'verifier'
            )


# ==============================================================================
# Token endpoint
# ==============================================================================


@pytest.mark.asyncio
class TestTokenRequests:
    async def test_exchange_code_sends_the_verifier(self, config):
        async with respx.mock:
            route = respx.post(TOKEN_URL).mock(return_value=_token_response())
            async with httpx.AsyncClient() as http:
                tokens = await oauth.exchange_code(
                    config, 'the-code', 'the-verifier', REDIRECT_URI, http
                )

            sent = parse_qs(route.calls.last.request.content.decode())
            assert sent['grant_type'] == ['authorization_code']
            assert sent['code'] == ['the-code']
            assert sent['code_verifier'] == ['the-verifier']
            assert sent['redirect_uri'] == [REDIRECT_URI]
            assert tokens.access_token == 'access-1'
            assert tokens.refresh_token == 'refresh-1'
            assert tokens.is_usable()

    async def test_public_client_sends_client_id_in_body(self, config):
        """No secret means no Basic header; the id goes in the form body."""
        async with respx.mock:
            route = respx.post(TOKEN_URL).mock(return_value=_token_response())
            async with httpx.AsyncClient() as http:
                await oauth.exchange_code(config, 'c', 'v', REDIRECT_URI, http)

            request = route.calls.last.request
            assert 'authorization' not in request.headers
            assert parse_qs(request.content.decode())['client_id'] == [
                'inspector'
            ]

    async def test_confidential_client_uses_basic_auth(
        self, confidential_config
    ):
        async with respx.mock:
            route = respx.post(TOKEN_URL).mock(return_value=_token_response())
            async with httpx.AsyncClient() as http:
                await oauth.exchange_code(
                    confidential_config, 'c', 'v', REDIRECT_URI, http
                )

            header = route.calls.last.request.headers['authorization']
            assert header.startswith('Basic ')
            decoded = base64.b64decode(header.split(' ', 1)[1]).decode()
            assert decoded == 'inspector:s3cret'

    async def test_token_exchange_grant(self, config):
        async with respx.mock:
            route = respx.post(TOKEN_URL).mock(return_value=_token_response())
            async with httpx.AsyncClient() as http:
                await oauth.exchange_subject_token(
                    config, 'upstream-token', http
                )

            sent = parse_qs(route.calls.last.request.content.decode())
            assert sent['grant_type'] == [oauth.GRANT_TOKEN_EXCHANGE]
            assert sent['subject_token'] == ['upstream-token']
            assert sent['subject_token_type'] == [oauth.TOKEN_TYPE_ACCESS_TOKEN]
            assert sent['resource'] == [AGENT_URL]
            assert sent['scope'] == ['a2a:message:send']

    async def test_refresh_carries_over_a_missing_refresh_token(self, config):
        """Providers may omit a new refresh token; the old one stays valid."""
        old = oauth.TokenSet('old', 'refresh-1', time.time() + 10)

        async with respx.mock:
            respx.post(TOKEN_URL).mock(
                return_value=_token_response(access='new', refresh=None)
            )
            async with httpx.AsyncClient() as http:
                renewed = await oauth.refresh_tokens(config, old, http)

        assert renewed.access_token == 'new'
        assert renewed.refresh_token == 'refresh-1'

    async def test_refresh_without_a_refresh_token(self, config):
        async with httpx.AsyncClient() as http:
            with pytest.raises(oauth.OAuthError, match='No refresh token'):
                await oauth.refresh_tokens(
                    config, oauth.TokenSet('only-access'), http
                )

    async def test_rfc6749_error_is_surfaced(self, config):
        async with respx.mock:
            respx.post(TOKEN_URL).mock(
                return_value=httpx.Response(
                    400,
                    json={
                        'error': 'invalid_grant',
                        'error_description': 'code expired',
                    },
                )
            )
            async with httpx.AsyncClient() as http:
                with pytest.raises(oauth.OAuthError) as excinfo:
                    await oauth.exchange_code(
                        config, 'c', 'v', REDIRECT_URI, http
                    )

        assert 'invalid_grant' in str(excinfo.value)
        assert 'code expired' in str(excinfo.value)

    async def test_response_without_access_token(self, config):
        async with respx.mock:
            respx.post(TOKEN_URL).mock(
                return_value=httpx.Response(200, json={'token_type': 'Bearer'})
            )
            async with httpx.AsyncClient() as http:
                with pytest.raises(oauth.OAuthError, match='no access_token'):
                    await oauth.exchange_code(
                        config, 'c', 'v', REDIRECT_URI, http
                    )

    async def test_unreachable_token_endpoint(self, config):
        async with respx.mock:
            respx.post(TOKEN_URL).mock(
                side_effect=httpx.ConnectError('refused')
            )
            async with httpx.AsyncClient() as http:
                with pytest.raises(oauth.OAuthError, match='Could not reach'):
                    await oauth.exchange_code(
                        config, 'c', 'v', REDIRECT_URI, http
                    )

    async def test_missing_expires_in_falls_back(self, config):
        """A response without expires_in still yields a usable token."""
        async with respx.mock:
            respx.post(TOKEN_URL).mock(
                return_value=httpx.Response(
                    200, json={'access_token': 'a', 'token_type': 'Bearer'}
                )
            )
            async with httpx.AsyncClient() as http:
                tokens = await oauth.exchange_code(
                    config, 'c', 'v', REDIRECT_URI, http
                )

        assert tokens.is_usable()


# ==============================================================================
# Credential service
# ==============================================================================


@pytest.mark.asyncio
class TestOAuthCredentialService:
    async def test_returns_none_without_a_session_id(self):
        """A context with no session must not raise -- the request proceeds."""
        service = oauth.OAuthCredentialService(httpx.AsyncClient())

        assert await service.get_credentials('AgentOAuth', None) is None
        assert (
            await service.get_credentials(
                'AgentOAuth', ClientCallContext(state={})
            )
            is None
        )

    async def test_returns_none_for_an_unauthenticated_scheme(self):
        service = oauth.OAuthCredentialService(httpx.AsyncClient())

        assert await service.get_credentials('AgentOAuth', _context()) is None

    async def test_valid_token_is_served_without_a_network_call(self, config):
        service = oauth.OAuthCredentialService(httpx.AsyncClient())
        service.store(
            'sid-1', config, oauth.TokenSet('good', 'r', time.time() + 3600)
        )

        async with respx.mock:
            route = respx.post(TOKEN_URL)
            token = await service.get_credentials('AgentOAuth', _context())

        assert token == 'good'
        assert not route.called

    async def test_expiring_token_is_refreshed(self, config):
        """The whole point: a short TTL never reaches the user."""
        async with httpx.AsyncClient() as http:
            service = oauth.OAuthCredentialService(http)
            service.store(
                'sid-1',
                config,
                oauth.TokenSet('stale', 'refresh-1', time.time() + 5),
            )

            async with respx.mock:
                route = respx.post(TOKEN_URL).mock(
                    return_value=_token_response(access='fresh')
                )
                first = await service.get_credentials('AgentOAuth', _context())
                # A second call inside the new lifetime must not hit the
                # endpoint again.
                second = await service.get_credentials('AgentOAuth', _context())

        assert first == 'fresh'
        assert second == 'fresh'
        assert route.call_count == 1

    async def test_failed_refresh_falls_back_to_the_old_token(self, config):
        """A 401 from the agent is clearer than an unauthenticated request."""
        async with httpx.AsyncClient() as http:
            service = oauth.OAuthCredentialService(http)
            service.store(
                'sid-1',
                config,
                oauth.TokenSet('stale', 'refresh-1', time.time() + 5),
            )

            async with respx.mock:
                respx.post(TOKEN_URL).mock(
                    return_value=httpx.Response(
                        400, json={'error': 'invalid_grant'}
                    )
                )
                token = await service.get_credentials('AgentOAuth', _context())

        assert token == 'stale'

    async def test_sessions_are_isolated(self, config):
        service = oauth.OAuthCredentialService(httpx.AsyncClient())
        service.store(
            'sid-1', config, oauth.TokenSet('a', None, time.time() + 3600)
        )

        assert (
            await service.get_credentials('AgentOAuth', _context('sid-2'))
            is None
        )

    async def test_purge_clears_a_session(self, config):
        service = oauth.OAuthCredentialService(httpx.AsyncClient())
        service.store(
            'sid-1', config, oauth.TokenSet('a', None, time.time() + 3600)
        )

        service.purge('sid-1')

        assert await service.get_credentials('AgentOAuth', _context()) is None

    async def test_authorization_round_trip(self, config):
        service = oauth.OAuthCredentialService(httpx.AsyncClient())
        url, state = service.begin_authorization('sid-1', config, REDIRECT_URI)

        async with respx.mock:
            route = respx.post(TOKEN_URL).mock(
                return_value=_token_response(access='from-code')
            )
            result = await service.complete_authorization(state, 'code-1')

        assert result.session_id == 'sid-1'
        assert result.scheme_name == 'AgentOAuth'
        assert result.token_set.access_token == 'from-code'
        assert state in url
        assert await service.get_credentials('AgentOAuth', _context()) == (
            'from-code'
        )
        # The verifier generated at begin_authorization must be the one
        # redeemed -- that is the entire point of PKCE.
        sent = parse_qs(route.calls.last.request.content.decode())
        assert oauth.code_challenge_for(sent['code_verifier'][0]) in url

    async def test_session_for_state_peeks_without_consuming(self, config):
        """An error from the provider must reach the right window."""
        service = oauth.OAuthCredentialService(httpx.AsyncClient())
        _, state = service.begin_authorization('sid-1', config, REDIRECT_URI)

        assert service.session_for_state(state) == 'sid-1'
        assert service.session_for_state('other') is None
        # Peeking must leave the authorization usable.
        assert service.session_for_state(state) == 'sid-1'

    async def test_unknown_state_is_rejected(self):
        service = oauth.OAuthCredentialService(httpx.AsyncClient())

        with pytest.raises(oauth.OAuthError, match='could not be matched'):
            await service.complete_authorization('never-issued', 'code-1')

    async def test_state_cannot_be_replayed(self, config):
        """A consumed state must not authorize a second callback."""
        service = oauth.OAuthCredentialService(httpx.AsyncClient())
        _, state = service.begin_authorization('sid-1', config, REDIRECT_URI)

        async with respx.mock:
            respx.post(TOKEN_URL).mock(return_value=_token_response())
            await service.complete_authorization(state, 'code-1')

            with pytest.raises(oauth.OAuthError):
                await service.complete_authorization(state, 'code-1')

    async def test_expired_state_is_rejected(self, config, monkeypatch):
        service = oauth.OAuthCredentialService(httpx.AsyncClient())
        _, state = service.begin_authorization('sid-1', config, REDIRECT_URI)

        expired_at = time.time() + oauth.PENDING_TTL_SECONDS + 1
        monkeypatch.setattr(oauth.time, 'time', lambda: expired_at)

        with pytest.raises(oauth.OAuthError, match='could not be matched'):
            await service.complete_authorization(state, 'code-1')

    async def test_purge_drops_pending_authorizations(self, config):
        service = oauth.OAuthCredentialService(httpx.AsyncClient())
        _, state = service.begin_authorization('sid-1', config, REDIRECT_URI)

        service.purge('sid-1')

        with pytest.raises(oauth.OAuthError):
            await service.complete_authorization(state, 'code-1')

    async def test_subject_token_authorization_stores_the_result(self, config):
        service = oauth.OAuthCredentialService(httpx.AsyncClient())

        async with respx.mock:
            respx.post(TOKEN_URL).mock(
                return_value=_token_response(access='exchanged')
            )
            await service.authorize_with_subject_token(
                'sid-1', config, 'upstream-token'
            )

        assert await service.get_credentials('AgentOAuth', _context()) == (
            'exchanged'
        )
