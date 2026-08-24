/**
 * Tests for authentication UI functionality
 */

import {describe, it, expect, beforeEach} from 'vitest';
import {fireEvent} from '@testing-library/dom';

describe('Authentication UI', () => {
  let authTypeSelect: HTMLSelectElement;
  let authInputsContainer: HTMLElement;

  beforeEach(() => {
    // Set up the DOM structure that matches the actual HTML
    document.body.innerHTML = `
      <div id="app">
        <select id="auth-type" class="auth-type-select">
          <option value="none">No Auth</option>
          <option value="basic">Basic Auth</option>
          <option value="bearer">Bearer Token</option>
          <option value="api-key">API Key</option>
          <option value="oauth2">OAuth 2.0</option>
        </select>
        <div id="auth-inputs" class="auth-inputs"></div>
        <div id="headers-list"></div>
      </div>
    `;

    authTypeSelect = document.getElementById('auth-type') as HTMLSelectElement;
    authInputsContainer = document.getElementById('auth-inputs') as HTMLElement;
  });

  describe('Auth Type Selection', () => {
    it('should have "none" selected by default', () => {
      expect(authTypeSelect.value).toBe('none');
    });

    it('should contain all auth type options', () => {
      const options = Array.from(authTypeSelect.options).map(opt => opt.value);
      expect(options).toEqual(['none', 'basic', 'bearer', 'api-key', 'oauth2']);
    });

    it('should change value when a different option is selected', () => {
      fireEvent.change(authTypeSelect, {target: {value: 'bearer'}});
      expect(authTypeSelect.value).toBe('bearer');
    });
  });

  describe('Auth Input Rendering - No Auth', () => {
    it('should not render any input fields for "none" auth type', () => {
      authTypeSelect.value = 'none';
      renderAuthInputs(authTypeSelect.value);

      expect(authInputsContainer.children.length).toBe(0);
    });
  });

  describe('Auth Input Rendering - Bearer Token', () => {
    beforeEach(() => {
      authTypeSelect.value = 'bearer';
      renderAuthInputs(authTypeSelect.value);
    });

    it('should render a token input field for bearer auth', () => {
      const tokenInput = document.getElementById(
        'bearer-token',
      ) as HTMLInputElement;
      expect(tokenInput).toBeTruthy();
      expect(tokenInput.type).toBe('password');
    });

    it('should have correct label for bearer token input', () => {
      const label = authInputsContainer.querySelector('label');
      expect(label?.textContent).toBe('Token');
    });

    it('should have correct placeholder for bearer token input', () => {
      const tokenInput = document.getElementById(
        'bearer-token',
      ) as HTMLInputElement;
      expect(tokenInput.placeholder).toBe('Enter your bearer token');
    });
  });

  describe('Auth Input Rendering - API Key', () => {
    beforeEach(() => {
      authTypeSelect.value = 'api-key';
      renderAuthInputs(authTypeSelect.value);
    });

    it('should render header name and API key input fields', () => {
      const headerInput = document.getElementById(
        'api-key-header',
      ) as HTMLInputElement;
      const keyInput = document.getElementById(
        'api-key-value',
      ) as HTMLInputElement;

      expect(headerInput).toBeTruthy();
      expect(keyInput).toBeTruthy();
    });

    it('should default header name to "X-API-Key"', () => {
      const headerInput = document.getElementById(
        'api-key-header',
      ) as HTMLInputElement;
      expect(headerInput.value).toBe('X-API-Key');
    });

    it('should use password type for API key input', () => {
      const keyInput = document.getElementById(
        'api-key-value',
      ) as HTMLInputElement;
      expect(keyInput.type).toBe('password');
    });

    it('should use grid layout for API key inputs', () => {
      const grid = authInputsContainer.querySelector('.auth-input-grid');
      expect(grid).toBeTruthy();
    });
  });

  describe('Auth Input Rendering - Basic Auth', () => {
    beforeEach(() => {
      authTypeSelect.value = 'basic';
      renderAuthInputs(authTypeSelect.value);
    });

    it('should render username and password input fields', () => {
      const usernameInput = document.getElementById(
        'basic-username',
      ) as HTMLInputElement;
      const passwordInput = document.getElementById(
        'basic-password',
      ) as HTMLInputElement;

      expect(usernameInput).toBeTruthy();
      expect(passwordInput).toBeTruthy();
    });

    it('should use text type for username input', () => {
      const usernameInput = document.getElementById(
        'basic-username',
      ) as HTMLInputElement;
      expect(usernameInput.type).toBe('text');
    });

    it('should use password type for password input', () => {
      const passwordInput = document.getElementById(
        'basic-password',
      ) as HTMLInputElement;
      expect(passwordInput.type).toBe('password');
    });

    it('should have correct placeholders for basic auth inputs', () => {
      const usernameInput = document.getElementById(
        'basic-username',
      ) as HTMLInputElement;
      const passwordInput = document.getElementById(
        'basic-password',
      ) as HTMLInputElement;

      expect(usernameInput.placeholder).toBe('Enter username');
      expect(passwordInput.placeholder).toBe('Enter password');
    });
  });

  describe('Auth Input Re-rendering', () => {
    it('should clear inputs when switching between auth types', () => {
      // Start with bearer
      authTypeSelect.value = 'bearer';
      renderAuthInputs(authTypeSelect.value);
      expect(authInputsContainer.children.length).toBeGreaterThan(0);

      // Switch to none
      authTypeSelect.value = 'none';
      renderAuthInputs(authTypeSelect.value);
      expect(authInputsContainer.children.length).toBe(0);

      // Switch to basic
      authTypeSelect.value = 'basic';
      renderAuthInputs(authTypeSelect.value);
      expect(authInputsContainer.children.length).toBe(2); // username + password groups
    });

    it('should replace inputs completely when changing types', () => {
      authTypeSelect.value = 'bearer';
      renderAuthInputs(authTypeSelect.value);

      const bearerInput = document.getElementById('bearer-token');
      expect(bearerInput).toBeTruthy();

      authTypeSelect.value = 'basic';
      renderAuthInputs(authTypeSelect.value);

      const bearerInputAfter = document.getElementById('bearer-token');
      expect(bearerInputAfter).toBeNull();

      const usernameInput = document.getElementById('basic-username');
      expect(usernameInput).toBeTruthy();
    });
  });
});

describe('Custom Header Generation', () => {
  let authTypeSelect: HTMLSelectElement;

  beforeEach(() => {
    document.body.innerHTML = `
      <div id="app">
        <select id="auth-type" class="auth-type-select">
          <option value="none">No Auth</option>
          <option value="basic">Basic Auth</option>
          <option value="bearer">Bearer Token</option>
          <option value="api-key">API Key</option>
          <option value="oauth2">OAuth 2.0</option>
        </select>
        <div id="auth-inputs" class="auth-inputs"></div>
        <div id="headers-list"></div>
      </div>
    `;
    authTypeSelect = document.getElementById('auth-type') as HTMLSelectElement;
  });

  describe('No Auth Headers', () => {
    it('should return empty headers object when no auth is selected', () => {
      authTypeSelect.value = 'none';
      const headers = getCustomHeaders();
      expect(headers).toEqual({});
    });
  });

  describe('Bearer Token Headers', () => {
    beforeEach(() => {
      authTypeSelect.value = 'bearer';
      renderAuthInputs(authTypeSelect.value);
    });

    it('should generate Authorization header with Bearer prefix', () => {
      const tokenInput = document.getElementById(
        'bearer-token',
      ) as HTMLInputElement;
      tokenInput.value = 'test-token-123';

      const headers = getCustomHeaders();
      expect(headers['Authorization']).toBe('Bearer test-token-123');
    });

    it('should not generate Authorization header if token is empty', () => {
      const tokenInput = document.getElementById(
        'bearer-token',
      ) as HTMLInputElement;
      tokenInput.value = '';

      const headers = getCustomHeaders();
      expect(headers['Authorization']).toBeUndefined();
    });

    it('should trim whitespace from bearer token', () => {
      const tokenInput = document.getElementById(
        'bearer-token',
      ) as HTMLInputElement;
      tokenInput.value = '  token-with-spaces  ';

      const headers = getCustomHeaders();
      expect(headers['Authorization']).toBe('Bearer token-with-spaces');
    });
  });

  describe('API Key Headers', () => {
    beforeEach(() => {
      authTypeSelect.value = 'api-key';
      renderAuthInputs(authTypeSelect.value);
    });

    it('should generate custom header with specified name', () => {
      const headerInput = document.getElementById(
        'api-key-header',
      ) as HTMLInputElement;
      const valueInput = document.getElementById(
        'api-key-value',
      ) as HTMLInputElement;

      headerInput.value = 'X-Custom-Key';
      valueInput.value = 'secret-key-456';

      const headers = getCustomHeaders();
      expect(headers['X-Custom-Key']).toBe('secret-key-456');
    });

    it('should use default X-API-Key header name', () => {
      const valueInput = document.getElementById(
        'api-key-value',
      ) as HTMLInputElement;
      valueInput.value = 'my-api-key';

      const headers = getCustomHeaders();
      expect(headers['X-API-Key']).toBe('my-api-key');
    });

    it('should not generate header if key value is empty', () => {
      const headerInput = document.getElementById(
        'api-key-header',
      ) as HTMLInputElement;
      const valueInput = document.getElementById(
        'api-key-value',
      ) as HTMLInputElement;

      headerInput.value = 'X-API-Key';
      valueInput.value = '';

      const headers = getCustomHeaders();
      expect(headers['X-API-Key']).toBeUndefined();
    });

    it('should not generate header if header name is empty', () => {
      const headerInput = document.getElementById(
        'api-key-header',
      ) as HTMLInputElement;
      const valueInput = document.getElementById(
        'api-key-value',
      ) as HTMLInputElement;

      headerInput.value = '';
      valueInput.value = 'my-key';

      const headers = getCustomHeaders();
      expect(Object.keys(headers).length).toBe(0);
    });
  });

  describe('Basic Auth Headers', () => {
    beforeEach(() => {
      authTypeSelect.value = 'basic';
      renderAuthInputs(authTypeSelect.value);
    });

    it('should generate Authorization header with Basic prefix and base64 encoding', () => {
      const usernameInput = document.getElementById(
        'basic-username',
      ) as HTMLInputElement;
      const passwordInput = document.getElementById(
        'basic-password',
      ) as HTMLInputElement;

      usernameInput.value = 'user123';
      passwordInput.value = 'pass456';

      const headers = getCustomHeaders();
      const expectedCredentials = btoa('user123:pass456');
      expect(headers['Authorization']).toBe(`Basic ${expectedCredentials}`);
    });

    it('should handle special characters in username and password', () => {
      const usernameInput = document.getElementById(
        'basic-username',
      ) as HTMLInputElement;
      const passwordInput = document.getElementById(
        'basic-password',
      ) as HTMLInputElement;

      usernameInput.value = 'user@example.com';
      passwordInput.value = 'p@ss:w0rd!';

      const headers = getCustomHeaders();
      const expectedCredentials = btoa('user@example.com:p@ss:w0rd!');
      expect(headers['Authorization']).toBe(`Basic ${expectedCredentials}`);
    });

    it('should not generate Authorization header if username is empty', () => {
      const usernameInput = document.getElementById(
        'basic-username',
      ) as HTMLInputElement;
      const passwordInput = document.getElementById(
        'basic-password',
      ) as HTMLInputElement;

      usernameInput.value = '';
      passwordInput.value = 'password';

      const headers = getCustomHeaders();
      expect(headers['Authorization']).toBeUndefined();
    });

    it('should not generate Authorization header if password is empty', () => {
      const usernameInput = document.getElementById(
        'basic-username',
      ) as HTMLInputElement;
      const passwordInput = document.getElementById(
        'basic-password',
      ) as HTMLInputElement;

      usernameInput.value = 'username';
      passwordInput.value = '';

      const headers = getCustomHeaders();
      expect(headers['Authorization']).toBeUndefined();
    });
  });

  describe('Custom Headers Integration', () => {
    beforeEach(() => {
      authTypeSelect.value = 'bearer';
      renderAuthInputs(authTypeSelect.value);
    });

    it('should merge auth headers with custom headers', () => {
      // Set up bearer token
      const tokenInput = document.getElementById(
        'bearer-token',
      ) as HTMLInputElement;
      tokenInput.value = 'bearer-token';

      // Add custom header
      const headersList = document.getElementById('headers-list')!;
      headersList.innerHTML = `
        <div class="header-item">
          <input class="header-name" value="X-Custom-Header" />
          <input class="header-value" value="custom-value" />
        </div>
      `;

      const headers = getCustomHeaders();
      expect(headers['Authorization']).toBe('Bearer bearer-token');
      expect(headers['X-Custom-Header']).toBe('custom-value');
    });

    it('should allow custom headers to override auth headers if specified', () => {
      // Set up bearer token
      const tokenInput = document.getElementById(
        'bearer-token',
      ) as HTMLInputElement;
      tokenInput.value = 'bearer-token';

      // Add custom Authorization header (this should override)
      const headersList = document.getElementById('headers-list')!;
      headersList.innerHTML = `
        <div class="header-item">
          <input class="header-name" value="Authorization" />
          <input class="header-value" value="Custom Auth Value" />
        </div>
      `;

      const headers = getCustomHeaders();
      // Custom headers are added after auth headers using Object.assign,
      // so custom headers should override
      expect(headers['Authorization']).toBe('Custom Auth Value');
    });

    it('should handle multiple custom headers with auth headers', () => {
      authTypeSelect.value = 'api-key';
      renderAuthInputs(authTypeSelect.value);

      const keyInput = document.getElementById(
        'api-key-value',
      ) as HTMLInputElement;
      keyInput.value = 'my-api-key';

      const headersList = document.getElementById('headers-list')!;
      headersList.innerHTML = `
        <div class="header-item">
          <input class="header-name" value="X-Request-ID" />
          <input class="header-value" value="req-123" />
        </div>
        <div class="header-item">
          <input class="header-name" value="X-Client-Version" />
          <input class="header-value" value="1.0.0" />
        </div>
      `;

      const headers = getCustomHeaders();
      expect(headers['X-API-Key']).toBe('my-api-key');
      expect(headers['X-Request-ID']).toBe('req-123');
      expect(headers['X-Client-Version']).toBe('1.0.0');
    });

    it('should skip empty custom headers', () => {
      authTypeSelect.value = 'none';

      const headersList = document.getElementById('headers-list')!;
      headersList.innerHTML = `
        <div class="header-item">
          <input class="header-name" value="" />
          <input class="header-value" value="value" />
        </div>
        <div class="header-item">
          <input class="header-name" value="Valid-Header" />
          <input class="header-value" value="valid-value" />
        </div>
      `;

      const headers = getCustomHeaders();
      expect(headers['Valid-Header']).toBe('valid-value');
      expect(Object.keys(headers).length).toBe(1);
    });
  });
});

// Helper functions that mirror the actual implementation
function createAuthInput(
  id: string,
  label: string,
  type: string,
  placeholder: string,
  defaultValue = '',
): HTMLElement {
  const group = document.createElement('div');
  group.className = 'auth-input-group';

  const labelEl = document.createElement('label');
  labelEl.htmlFor = id;
  labelEl.textContent = label;

  const inputEl = document.createElement('input');
  inputEl.type = type;
  inputEl.id = id;
  inputEl.placeholder = placeholder;
  inputEl.value = defaultValue;

  group.appendChild(labelEl);
  group.appendChild(inputEl);
  return group;
}

function renderAuthInputs(authType: string) {
  const authInputsContainer = document.getElementById('auth-inputs')!;
  authInputsContainer.replaceChildren();

  switch (authType) {
    case 'bearer':
      authInputsContainer.appendChild(
        createAuthInput(
          'bearer-token',
          'Token',
          'password',
          'Enter your bearer token',
        ),
      );
      break;

    case 'api-key': {
      const grid = document.createElement('div');
      grid.className = 'auth-input-grid';
      grid.appendChild(
        createAuthInput(
          'api-key-header',
          'Header Name',
          'text',
          'e.g., X-API-Key',
          'X-API-Key',
        ),
      );
      grid.appendChild(
        createAuthInput(
          'api-key-value',
          'API Key',
          'password',
          'Enter your API key',
        ),
      );
      authInputsContainer.appendChild(grid);
      break;
    }

    case 'basic':
      authInputsContainer.appendChild(
        createAuthInput('basic-username', 'Username', 'text', 'Enter username'),
      );
      authInputsContainer.appendChild(
        createAuthInput(
          'basic-password',
          'Password',
          'password',
          'Enter password',
        ),
      );
      break;

    case 'none':
    default:
      break;
  }
}

function getInputValue(id: string): string {
  const input = document.getElementById(id) as HTMLInputElement;
  return input?.value.trim() || '';
}

function getCustomHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  const authTypeSelect = document.getElementById(
    'auth-type',
  ) as HTMLSelectElement;
  const authType = authTypeSelect.value;

  // Add auth headers based on selected type
  switch (authType) {
    case 'bearer': {
      const token = getInputValue('bearer-token');
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      break;
    }

    case 'api-key': {
      const headerName = getInputValue('api-key-header');
      const value = getInputValue('api-key-value');
      if (headerName && value) {
        headers[headerName] = value;
      }
      break;
    }

    case 'basic': {
      const username = getInputValue('basic-username');
      const password = getInputValue('basic-password');
      if (username && password) {
        const credentials = btoa(`${username}:${password}`);
        headers['Authorization'] = `Basic ${credentials}`;
      }
      break;
    }

    case 'none':
    default:
      break;
  }

  // Always add custom headers from the header list
  const headersList = document.getElementById('headers-list')!;
  const headerItems = headersList.querySelectorAll('.header-item');

  headerItems.forEach(item => {
    const nameInput = item.querySelector('.header-name') as HTMLInputElement;
    const valueInput = item.querySelector('.header-value') as HTMLInputElement;

    const name = nameInput?.value.trim();
    const value = valueInput?.value.trim();

    if (name && value) {
      headers[name] = value;
    }
  });

  return headers;
}

/**
 * OAuth2 panel.
 *
 * Like the rest of this file, the production logic is mirrored here rather
 * than imported, because src/script.ts is one big DOMContentLoaded closure
 * with no exports. buildOAuthPanel is reproduced with its module state
 * passed in, so the rendering rules stay under test.
 */
interface TestOAuthScheme {
  schemeName: string;
  authorizationUrl: string | null;
  tokenUrl: string;
  availableScopes: string[];
  requiredScopes: string[];
  required: boolean;
}

function buildOAuthPanel(
  container: HTMLElement,
  schemes: Record<string, TestOAuthScheme>,
  isConnected: boolean,
) {
  container.replaceChildren();
  const names = Object.keys(schemes);

  if (names.length === 0) {
    const hint = document.createElement('p');
    hint.className = 'placeholder-text';
    hint.textContent = isConnected
      ? 'This agent card declares no OAuth2 security scheme.'
      : 'Connect to an agent first — its card supplies the OAuth endpoints.';
    container.appendChild(hint);
    return;
  }

  if (names.length > 1) {
    const select = document.createElement('select');
    select.id = 'oauth-scheme';
    for (const name of names) {
      const option = document.createElement('option');
      option.value = name;
      option.textContent = name;
      select.appendChild(option);
    }
    container.appendChild(select);
  }

  const scheme = schemes[names[0]];
  const scopes = (
    scheme.requiredScopes.length
      ? scheme.requiredScopes
      : scheme.availableScopes
  ).join(' ');

  container.appendChild(
    createAuthInput('oauth-client-id', 'Client ID', 'text', ''),
  );
  container.appendChild(
    createAuthInput(
      'oauth-client-secret',
      'Client Secret (optional)',
      'password',
      '',
    ),
  );
  container.appendChild(
    createAuthInput('oauth-scopes', 'Scopes', 'text', '', scopes),
  );

  const actions = document.createElement('div');
  actions.className = 'oauth-actions';
  if (scheme.authorizationUrl) {
    const loginBtn = document.createElement('button');
    loginBtn.id = 'oauth-login-btn';
    loginBtn.textContent = 'Log in';
    actions.appendChild(loginBtn);
  }
  const exchangeBtn = document.createElement('button');
  exchangeBtn.id = 'oauth-exchange-btn';
  exchangeBtn.textContent = 'Exchange token';
  actions.appendChild(exchangeBtn);
  container.appendChild(actions);

  container.appendChild(
    createAuthInput(
      'oauth-subject-token',
      'Subject Token (for exchange only)',
      'password',
      '',
    ),
  );
}

describe('OAuth2 Panel', () => {
  let container: HTMLElement;

  const scheme = (
    overrides: Partial<TestOAuthScheme> = {},
  ): TestOAuthScheme => ({
    schemeName: 'AgentOAuth',
    authorizationUrl: 'https://agent.example/oauth/authorize',
    tokenUrl: 'https://agent.example/oauth/token',
    availableScopes: ['a2a:message:send', 'a2a:task:read'],
    requiredScopes: ['a2a:message:send'],
    required: true,
    ...overrides,
  });

  beforeEach(() => {
    document.body.innerHTML =
      '<div id="auth-inputs" class="auth-inputs"></div>';
    container = document.getElementById('auth-inputs') as HTMLElement;
  });

  it('tells the user to connect before any card is available', () => {
    buildOAuthPanel(container, {}, false);

    expect(container.textContent).toContain('Connect to an agent first');
    expect(container.querySelector('#oauth-client-id')).toBeNull();
  });

  it('reports when a connected agent declares no OAuth scheme', () => {
    buildOAuthPanel(container, {}, true);

    expect(container.textContent).toContain('no OAuth2 security scheme');
  });

  it('renders the credential fields once a scheme is known', () => {
    buildOAuthPanel(container, {AgentOAuth: scheme()}, true);

    expect(container.querySelector('#oauth-client-id')).not.toBeNull();
    expect(container.querySelector('#oauth-client-secret')).not.toBeNull();
    expect(container.querySelector('#oauth-scopes')).not.toBeNull();
  });

  it('prefills the scopes the card requires', () => {
    buildOAuthPanel(container, {AgentOAuth: scheme()}, true);

    const scopes = container.querySelector('#oauth-scopes') as HTMLInputElement;
    expect(scopes.value).toBe('a2a:message:send');
  });

  it('falls back to the declared scopes when none are required', () => {
    buildOAuthPanel(
      container,
      {AgentOAuth: scheme({requiredScopes: [], required: false})},
      true,
    );

    const scopes = container.querySelector('#oauth-scopes') as HTMLInputElement;
    expect(scopes.value).toBe('a2a:message:send a2a:task:read');
  });

  it('offers an interactive login when the scheme has an authorization endpoint', () => {
    buildOAuthPanel(container, {AgentOAuth: scheme()}, true);

    expect(container.querySelector('#oauth-login-btn')).not.toBeNull();
  });

  it('hides the login button for exchange-only providers', () => {
    // An authorization server offering only token-exchange has no
    // authorization endpoint, so there is nothing to log in to.
    buildOAuthPanel(
      container,
      {AgentOAuth: scheme({authorizationUrl: null})},
      true,
    );

    expect(container.querySelector('#oauth-login-btn')).toBeNull();
    expect(container.querySelector('#oauth-exchange-btn')).not.toBeNull();
  });

  it('leaves the client secret empty so PKCE is the default', () => {
    buildOAuthPanel(container, {AgentOAuth: scheme()}, true);

    const secret = container.querySelector(
      '#oauth-client-secret',
    ) as HTMLInputElement;
    expect(secret.value).toBe('');
    expect(secret.type).toBe('password');
  });

  it('lets the user pick when the card declares several schemes', () => {
    buildOAuthPanel(
      container,
      {
        AgentOAuth: scheme(),
        Other: scheme({schemeName: 'Other'}),
      },
      true,
    );

    const select = container.querySelector(
      '#oauth-scheme',
    ) as HTMLSelectElement;
    expect(select).not.toBeNull();
    expect(Array.from(select.options).map(o => o.value)).toEqual([
      'AgentOAuth',
      'Other',
    ]);
  });

  it('omits the scheme picker when there is only one', () => {
    buildOAuthPanel(container, {AgentOAuth: scheme()}, true);

    expect(container.querySelector('#oauth-scheme')).toBeNull();
  });

  it('keeps secret-bearing fields out of the DOM as plain text', () => {
    buildOAuthPanel(container, {AgentOAuth: scheme()}, true);

    for (const id of ['#oauth-client-secret', '#oauth-subject-token']) {
      const input = container.querySelector(id) as HTMLInputElement;
      expect(input.type).toBe('password');
    }
  });
});
