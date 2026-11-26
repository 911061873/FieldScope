const TOKEN_KEY = "fieldscope_admin_token";

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token: string | null): void {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

export async function apiRequest<T>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    query?: Record<string, string | number | undefined | null>;
    auth?: boolean;
  } = {}
): Promise<T> {
  const { method = "GET", body, query, auth = true } = options;

  let url = path;
  if (query) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== "") {
        params.set(k, String(v));
      }
    }
    const qs = params.toString();
    if (qs) {
      url += (url.includes("?") ? "&" : "?") + qs;
    }
  }

  const headers: Record<string, string> = {};
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (auth) {
    const token = getStoredToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }

  const resp = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (resp.status === 401 && auth) {
    setStoredToken(null);
    if (window.location.pathname !== "/login") {
      window.location.href = "/login";
    }
  }

  const text = await resp.text();
  let parsed: any = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }
  }

  if (!resp.ok) {
    const detail =
      typeof parsed === "object" && parsed?.detail
        ? typeof parsed.detail === "string"
          ? parsed.detail
          : JSON.stringify(parsed.detail)
        : `请求失败 (HTTP ${resp.status})`;
    throw new ApiError(resp.status, detail);
  }

  return parsed as T;
}
