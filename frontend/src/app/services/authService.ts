export interface AuthUser {
  id: string;
  username: string;
  authenticated: boolean;
  role: string;
}

export interface AuthState {
  authEnabled: boolean;
  user: AuthUser;
}

interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user?: AuthUser;
}

const TOKEN_KEY = "elevadr-auth-token";
export const AUTH_EXPIRED_EVENT = "elevadr-auth-expired";

export function authApiUrl(path: string): string {
  const env = (import.meta as ImportMeta & { env?: Record<string, string | undefined> }).env;
  const explicitBase = env?.VITE_AUTH_BASE_URL?.trim();
  if (explicitBase) return `${explicitBase.replace(/\/$/, "")}${path}`;

  const configuredApi = [
    env?.VITE_DETECTION_ANALYSIS_URL,
    env?.VITE_PCAP_ANALYSIS_URL,
    env?.VITE_PCAP_CONTEXT_DISCOVERY_URL,
  ].map((value) => value?.trim()).find(Boolean);

  if (configuredApi) {
    try {
      return `${new URL(configuredApi, window.location.origin).origin}${path}`;
    } catch { /* fall through to same-origin */ }
  }
  return path;
}

export function getAccessToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function clearAccessToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

function storeAccessToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

async function responseMessage(response: Response): Promise<string> {
  try {
    const payload = await response.clone().json() as { message?: unknown; error?: unknown };
    if (typeof payload.message === "string" && payload.message) return payload.message;
    if (typeof payload.error === "string" && payload.error) return payload.error;
  } catch { /* use fallback */ }
  return `Request failed with status ${response.status}`;
}

export async function fetchAuthState(): Promise<AuthState> {
  const token = getAccessToken();
  const response = await fetch(authApiUrl("/auth/me"), {
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    cache: "no-store",
  });
  if (response.status === 401) {
    clearAccessToken();
    return { authEnabled: true, user: { id: "", username: "", authenticated: false, role: "anonymous" } };
  }
  if (!response.ok) throw new Error(await responseMessage(response));
  return await response.json() as AuthState;
}

export async function login(username: string, password: string): Promise<AuthState> {
  const response = await fetch(authApiUrl("/auth/login"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new Error(await responseMessage(response));
  const payload = await response.json() as LoginResponse;
  if (!payload.access_token) throw new Error("Authentication response did not include an access token.");
  storeAccessToken(payload.access_token);
  return await fetchAuthState();
}

export async function logout(): Promise<void> {
  const token = getAccessToken();
  try {
    await fetch(authApiUrl("/auth/logout"), {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    });
  } finally {
    clearAccessToken();
  }
}

export async function authenticatedFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const token = getAccessToken();
  const headers = new Headers(init.headers || undefined);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(input, { ...init, headers });
  if (response.status === 401 && token) {
    clearAccessToken();
    window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
  }
  return response;
}
