// Support both VITE_API_BASE and VITE_API_BASE_URL, stripping trailing slash or duplicate /api
const rawBase = (typeof import.meta !== "undefined" && ((import.meta as any).env?.VITE_API_BASE || (import.meta as any).env?.VITE_API_BASE_URL) as string | undefined) ?? "";
const cleanBase = rawBase.replace(/\/api\/?$/, "").replace(/\/+$/, "");
const BASE = cleanBase;

export class ApiError extends Error {
  constructor(public code: string, message: string, public status = 0) {
    super(message);
    this.name = "ApiError";
  }
}

const MESSAGES: Record<string, string> = {
  backend_not_configured: "The reporting service is not configured for this build.",
  network: "The reporting service could not be reached. Ensure the API server is active on port 4000.",
  credential_expired: "Your reporting credential has expired. Re-enroll to continue.",
  invalid_proof: "The eligibility proof could not be verified.",
  duplicate: "A submission already exists for this reporting scope.",
  invalid_credentials: "The provided status access secret is invalid.",
  not_found: "The requested record was not found.",
  unauthorized: "You are not authorized to view this resource.",
  invalid_body: "Report body must be between 20 and 5000 characters.",
  invalid_category: "A valid report category must be selected.",
  invalid_reason: "Action reason must be at least 5 characters.",
  unknown: "The request failed. Please check parameters and try again.",
};

// Moderator Token Management for Local Development Demo
let moderatorToken: string | null = null;

export function getModeratorToken(): string | null {
  if (moderatorToken) return moderatorToken;
  if (typeof window !== "undefined" && window.sessionStorage) {
    moderatorToken = sessionStorage.getItem("incognito_dev_mod_token");
  }
  return moderatorToken;
}

export function setModeratorToken(token: string | null): void {
  moderatorToken = token;
  if (typeof window !== "undefined" && window.sessionStorage) {
    if (token) {
      sessionStorage.setItem("incognito_dev_mod_token", token);
    } else {
      sessionStorage.removeItem("incognito_dev_mod_token");
    }
  }
}

export async function fetchDevModeratorToken(): Promise<string | null> {
  try {
    const url = BASE ? `${BASE}/api/auth/dev-moderator-token` : "/api/auth/dev-moderator-token";
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sub: "dev-moderator-01" }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data.token) {
      setModeratorToken(data.token);
      return data.token;
    }
  } catch {
    // Network or dev auth unavailable
  }
  return null;
}

export async function request<T>(
  path: string,
  init: { method?: string; body?: unknown; idempotencyKey?: string } = {}
): Promise<T> {
  const url = BASE ? `${BASE}${path}` : path;
  let token: string | null = null;

  if (path.startsWith("/api/moderator") || path.startsWith("/api/audit") || path.startsWith("/api/security")) {
    token = getModeratorToken();
    if (!token) {
      token = await fetchDevModeratorToken();
    }
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.idempotencyKey ? { "Idempotency-Key": init.idempotencyKey } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  let res: Response;

  try {
    res = await fetch(url, {
      method: init.method ?? "GET",
      credentials: "include",
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
  } catch {
    throw new ApiError("network", MESSAGES.network);
  }

  // If a 401 unauthenticated response is returned on a moderator route, try refreshing the token once
  if (res.status === 401 && (path.startsWith("/api/moderator") || path.startsWith("/api/audit") || path.startsWith("/api/security"))) {
    const freshToken = await fetchDevModeratorToken();
    if (freshToken) {
      headers["Authorization"] = `Bearer ${freshToken}`;
      try {
        res = await fetch(url, {
          method: init.method ?? "GET",
          credentials: "include",
          headers,
          body: init.body === undefined ? undefined : JSON.stringify(init.body),
        });
      } catch {
        throw new ApiError("network", MESSAGES.network);
      }
    }
  }

  if (!res.ok) {
    let code = "unknown";
    let message = "";
    try {
      const data = await res.json();
      code = data.code || data.error || code;
      message = data.message || "";
    } catch {
      /* body not JSON */
    }

    if (res.status === 401 || res.status === 403) {
      if (!code || code === "unknown") code = "unauthorized";
    }

    const finalMessage = message || MESSAGES[code] || MESSAGES.unknown;
    throw new ApiError(code, finalMessage, res.status);
  }

  return (await res.json()) as T;
}
