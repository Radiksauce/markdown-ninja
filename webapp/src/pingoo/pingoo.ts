import { jwtDecode } from "./jwt_decode";

const NETWORK_ERROR_MESSAGE = 'Network error. Please try again.';

const AUTH_STORAGE_KEY = '__pingoo_auth';
const REFRESH_TOKEN_STORAGE_KEY = '__pingoo_refresh_token';

// const OIDC_ERROR_INVALID_GRANT = 'invalid_grant';
const GET_ACCESS_TOKEN_LOCK_NAME = `__pingoo_get_access_token-${window.location.host}`;
const REFRESH_TOKENS_LOCK_NAME = `__pingoo_refresh_tokens-${window.location.host}`;


let pingooClient: PingooClient | null = null;

export function createPingooClient(config: PingooClientConfig): PingooClient {
  pingooClient = new PingooClient(config);
  return pingooClient;
}

export function usePingoo(): PingooClient {
  if (!pingooClient) {
  throw new Error('pingoo should be created before using it');
  }
  return pingooClient!;
}


export type PingooClientConfig = {
  endpoint: string,
  appId: string,
  redirectUri: string,
};

export type PingooAuthStoredState = {
  state: string,
  redirectUri: string,
  codeVerifier: string,
}

export type OidcError = {
  error: string,
  error_description: string,
}

export type OidcTokenResponse = {
  access_token: string,
  token_type: string,
  expires_in: number,
  refresh_token: string,
  scope: string,
  id_token?: string,
}

export type PingooParsedRefreshToken = {
  exp: number,
}

export type AccessTokenClaims = {
  sub: string,
  exp: number,
  email: string,
  name: string,
  is_admin: boolean,
}

export type User = {
  id: string,
  email: string,
  is_admin: boolean,
}

function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_STORAGE_KEY);
}

function setRefreshToken(token: string) {
  return localStorage.setItem(REFRESH_TOKEN_STORAGE_KEY, token);
}

function deleteRefreshToken() {
  return localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY);
}

export class PingooClient {
  private endpoint: string;
  private appId: string;
  private redirectUri: string;
  private accessToken: string | null;
  private accessTokenClaims: AccessTokenClaims | null;
  // private currentUser: User | null;
  private accessTokenBroadcastChannel: BroadcastChannel;

  constructor(config: PingooClientConfig) {
    this.accessTokenBroadcastChannel = new BroadcastChannel('__pingoo_access_token_boradcast_channel')
    this.endpoint = config.endpoint;
    this.appId = config.appId;
    this.redirectUri = config.redirectUri;

    const refreshToken = getRefreshToken();
    if (refreshToken) {
      const nowUnix = getUnixTimestamp();
      const parsedRefreshToken: PingooParsedRefreshToken = jwtDecode(refreshToken);
      // if the refresh token is about to expire, we act like if we are not authenticated.
      // TODO: improve
      if (parsedRefreshToken.exp <= (nowUnix - 3600)) {
        deleteRefreshToken();
      }
    }

    this.accessToken = null;
    this.accessTokenClaims = null;
    // this.currentUser = null;

    this.accessTokenBroadcastChannel.onmessage = (event) => {
      if (event.data && typeof event.data === 'string') {
        this.accessToken = event.data;
        this.accessTokenClaims = jwtDecode(this.accessToken);
      } else if (event.data === null) {
        this.logout(false);
      }
    }
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////
  // public methods
  //////////////////////////////////////////////////////////////////////////////////////////////////
  async init() {
    if (!this.isAuthenticated()) {
      return;
    }
    try {
      await this.refreshTokens();
    } catch (_) {
      this.logout();
    }
  }


  async signup() {
    return this.authorize('signup');
  }

  async login() {
    return this.authorize('login');
  }

  private async authorize(action: string) {
    // generate the required values
    let state = generateRandomString(32);
    let codeVerifier = generateRandomString(32);
    let codeChallenge = b64ToB64UrlNoPadding(btoa(uint8ArrayToString(await hashStringSha256(codeVerifier))));

    // save state to be used after authentication
    let storedState: PingooAuthStoredState = {
      state,
      redirectUri: this.redirectUri,
      codeVerifier,
    };
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(storedState));

    // generate and redirect to the auth URL
    let authUrl = new URL(this.endpoint);
    authUrl.pathname = '/authorize';
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('client_id', this.appId);
    authUrl.searchParams.append('redirect_uri', this.redirectUri);
    authUrl.searchParams.append('scope', 'openid offline_access');
    authUrl.searchParams.append('state', state);
    authUrl.searchParams.append('response_mode', 'query');
    authUrl.searchParams.append('code_challenge_method', 'S256');
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('action', action);

    window.location.href = authUrl.toString();
  }


  async logout(broadcast = true) {
    this.accessToken = null;
    this.accessTokenClaims = null;
    if (broadcast) {
      this.accessTokenBroadcastChannel.postMessage(null);
    }
    localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY);
    localStorage.removeItem(AUTH_STORAGE_KEY);
  }

  async handleSignInCallback(urlStr: string) {
    let url = new URL(urlStr);
    let state = url.searchParams.get('state') ?? '';
    let code = url.searchParams.get('code') ?? '';

    let storedState: PingooAuthStoredState = JSON.parse(localStorage.getItem(AUTH_STORAGE_KEY) ?? '{}');

    if (storedState.state !== state) {
      throw new Error('state is not valid');
    }

    try {
      const response = await fetch(`${this.endpoint}/oidc/token`, {
        method: 'POST',
        headers:  {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: this.appId,
          redirect_uri: storedState.redirectUri,
          code: code,
          code_verifier: storedState.codeVerifier,
        }).toString(),
      });

      if (response.status > 399) {
        let error: OidcError = await response.json();
        console.error(`${error.error}: ${error.error_description}`);
        throw new Error(error.error_description);
      }

      localStorage.removeItem(AUTH_STORAGE_KEY);

      const tokens: OidcTokenResponse = await response.json();

      // parse and save tokens
      setRefreshToken(tokens.refresh_token);

      this.accessToken = tokens.access_token;
      this.accessTokenClaims = jwtDecode(tokens.access_token);
      this.accessTokenBroadcastChannel.postMessage(tokens.access_token);
    } catch (err: any) {
      throw new Error(err.message);
    }
  }

  // getAccessToken returns an access token, and fetch a new one if needed
  async getAccessToken(): Promise<string> {
    if (navigator.locks) {
      return await navigator.locks.request(GET_ACCESS_TOKEN_LOCK_NAME, async (_) => {
        return await this._getAccessToken();
      });
    } else {
      return await this._getAccessToken();
    }
  }

  isAuthenticated(): boolean {
    return getRefreshToken() != null;
  }

  async getAccessTokenClaims(): Promise<AccessTokenClaims> {
    // first get an access token and refresh it if needed
    await this.getAccessToken();
    return this.accessTokenClaims!;
  }

  accountUrl(): string {
    return this.endpoint;
  }

  signupUrl(): string {
    return `${this.endpoint}/signup`;
  }

  async getUserInfo(): Promise<User> {
    if (!this.isAuthenticated()) {
      throw new Error('Authentication required');
    }

    const headers = new Headers();
    headers.set('Accept', 'application/json');
    if (this.isAuthenticated()) {
      headers.set('Authorization', `Bearer ${await this.getAccessToken()}`);
    }

    let response: Response | null = null;
    try {
      response = await fetch(`${this.endpoint}/oidc/userinfo`, {
        method: 'GET',
        headers,
      });
    } catch (err: any) {
      throw new Error(NETWORK_ERROR_MESSAGE);
    }

    if (response.status > 399) {
      let error: OidcError = await response.json();
      console.error(`${error.error}: ${error.error_description}`);
      throw new Error(error.error_description);
    }

    return response.json();
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////
  // private methods
  //////////////////////////////////////////////////////////////////////////////////////////////////
  private async _getAccessToken(): Promise<string> {
    let nowUnix = getUnixTimestamp();
    // if we don't have an access token yet, or if the access token has expired
    if (!this.accessToken || (this.accessTokenClaims?.exp ?? 0) <= (nowUnix - 10)) {
      await this.refreshTokens();
    }

    return this.accessToken!;
  }

  // refresh both the access token and the refresh token
  // and return the new access token
  private async refreshTokens() {
    if (navigator.locks) {
      await navigator.locks.request(REFRESH_TOKENS_LOCK_NAME, async (_) => {
        await this._refreshTokens();
      });
    } else {
      await this._refreshTokens();
    }
  }

  private async _refreshTokens() {
    const response = await fetch(`${this.endpoint}/oidc/token`, {
      method: 'POST',
      headers:  {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: getRefreshToken()!,
        scope: 'openid offline_access',
      }).toString(),
    });

    if (response.status > 399) {
      let error: OidcError = await response.json();
      // if (error.error === OIDC_ERROR_INVALID_GRANT) {
      //   this.logout();
      // }
      console.error(`${error.error}: ${error.error_description}`);
      throw new Error(error.error_description);
    }

    const tokens: OidcTokenResponse = await response.json();

    // parse and save tokens
    setRefreshToken(tokens.refresh_token);

    this.accessToken = tokens.access_token;
    this.accessTokenClaims = jwtDecode(tokens.access_token);
    this.accessTokenBroadcastChannel.postMessage(tokens.access_token);
  }

  async get(route: string, headersInput?: Headers): Promise<any> {
    const url = `${this.endpoint}/api${route}`;
    let response: any = null;

    const headers = new Headers();
    headers.set('Accept', 'application/json');
    if (this.isAuthenticated()) {
      headers.set('Authorization', `Bearer ${await this.getAccessToken()}`);
    }

    if (headersInput) {
      for (let [headerName, headerValue] of headersInput) {
        headers.set(headerName, headerValue);
      }
    }

    try {
      response = await fetch(url, {
        method: 'GET',
        headers,
      });
    } catch (err: any) {
      throw new Error(NETWORK_ERROR_MESSAGE);
    }

    const responseData = await this.unwrapApiResponse(response);
    return responseData;
  }

  private async unwrapApiResponse(response: Response): Promise<any>  {
    const apiRes: any = await response.json();

    if (response.status >= 400) {
      throw new Error(apiRes.message);
    }

    return apiRes;
  }
}

function getUnixTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}


export function uint8ArrayToHex(input: Uint8Array) {
  return Array.from(input)
      .map(byte => byte.toString(16).padStart(2, '0')) // Convert each byte to hex and pad with zeros
      .join(''); // Join all hex values into a single string
}

function generateRandomString(byteLength: number) {
  const buffer = new Uint8Array(byteLength);
  window.crypto.getRandomValues(buffer);
  return b64ToB64UrlNoPadding(btoa(uint8ArrayToString(buffer)));
}

function uint8ArrayToString(input: Uint8Array): string {
  let output = '';
  for (let i = 0; i < input.length; i++) {
    output += String.fromCharCode(input[i]);
  }
  return output;
}

function b64ToB64UrlNoPadding(input: string): string {
  return input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hashStringSha256(input: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}
