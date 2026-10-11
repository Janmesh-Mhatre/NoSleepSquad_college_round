// Support both VITE_API_BASE and VITE_API_BASE_URL, stripping trailing slash or duplicate /api
const envObj = typeof import.meta !== "undefined" ? (import.meta as any).env : undefined;
const rawBase: string = typeof envObj?.VITE_API_BASE === "string" ? envObj.VITE_API_BASE : (typeof envObj?.VITE_API_BASE_URL === "string" ? envObj.VITE_API_BASE_URL : "");
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

// Development Token Management for Local Development Demo
let moderatorToken: string | null = null;
let adminToken: string | null = null;

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

export function getAdminToken(): string | null {
  if (adminToken) return adminToken;
  if (typeof window !== "undefined" && window.sessionStorage) {
    adminToken = sessionStorage.getItem("incognito_dev_admin_token");
  }
  return adminToken;
}

export function setAdminToken(token: string | null): void {
  adminToken = token;
  if (typeof window !== "undefined" && window.sessionStorage) {
    if (token) {
      sessionStorage.setItem("incognito_dev_admin_token", token);
    } else {
      sessionStorage.removeItem("incognito_dev_admin_token");
    }
  }
}

export async function fetchDevModeratorToken(): Promise<string | null> {
  const cached = getModeratorToken();
  if (cached) return cached;

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

export async function fetchDevAdminToken(): Promise<string | null> {
  const cached = getAdminToken();
  if (cached) return cached;

  try {
    const url = BASE ? `${BASE}/api/auth/dev-token` : "/api/auth/dev-token";
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sub: "dev-admin-01", role: "admin" }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data.token) {
      setAdminToken(data.token);
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

  const isAdminRoute = path.startsWith("/api/security") || path.startsWith("/api/system");
  const isModeratorRoute = path.startsWith("/api/moderator");
  const isAuditRoute = path.startsWith("/api/audit");
  const inAdminConsole = typeof window !== "undefined" && window.location?.pathname?.startsWith("/admin");

  if (isAdminRoute || (isAuditRoute && inAdminConsole)) {
    token = getAdminToken();
    if (!token) {
      token = await fetchDevAdminToken();
    }
  } else if (isModeratorRoute || isAuditRoute) {
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

  // If a 401 unauthenticated response is returned, attempt one token refresh
  if (res.status === 401) {
    let freshToken: string | null = null;
    if (isAdminRoute || (isAuditRoute && inAdminConsole)) {
      setAdminToken(null);
      freshToken = await fetchDevAdminToken();
    } else if (isModeratorRoute || isAuditRoute) {
      setModeratorToken(null);
      freshToken = await fetchDevModeratorToken();
    }

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
