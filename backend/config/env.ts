import path from "node:path";

const toInt = (value: string | undefined, fallback: number): number => {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const toList = (value: string | undefined): string[] =>
  (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

const rawNodeEnv = (process.env.NODE_ENV || "development").toLowerCase();
const isProduction = rawNodeEnv === "production";
const isStaging = rawNodeEnv === "staging";
const isDeployedEnv = isProduction || isStaging;
const isDevelopment = !isDeployedEnv && (rawNodeEnv === "development" || rawNodeEnv === "test");
const allowDevAuth = isDevelopment && (process.env.ALLOW_DEV_AUTH === "true" || process.env.DEV_AUTH_ENABLED === "true");

/**
 * Validates security invariants at application startup.
 * Staging is treated as security-equivalent to production.
 * Insecure developer bypasses are strictly prevented from executing in staging or production.
 */
export function assertEnvironmentSecurity(): void {
  const currentEnv = (process.env.NODE_ENV || "development").toLowerCase();
  const isDeployed = currentEnv === "production" || currentEnv === "staging";
  const hasDevAuthFlag = process.env.ALLOW_DEV_AUTH === "true" || process.env.DEV_AUTH_ENABLED === "true";

  if (isDeployed && hasDevAuthFlag) {
    throw new Error(
      "FATAL SECURITY MISCONFIGURATION: ALLOW_DEV_AUTH / DEV_AUTH_ENABLED is strictly prohibited in deployed environments (staging / production). Application refusing to start."
    );
  }

  if (isDeployed) {
    const rawAuthSecret = process.env.AUTH_SECRET;
    if (!rawAuthSecret || rawAuthSecret.length < 32 || rawAuthSecret.includes("dev-only")) {
      throw new Error(
        `FATAL: ${currentEnv.toUpperCase()} requires a securely injected AUTH_SECRET with at least 32 characters.`
      );
    }
    const rawEncryptionKey = process.env.ENCRYPTION_KEY;
    if (!rawEncryptionKey || rawEncryptionKey.length < 32 || rawEncryptionKey.includes("dev-only")) {
      throw new Error(
        `FATAL: ${currentEnv.toUpperCase()} requires a securely injected ENCRYPTION_KEY with at least 32 characters.`
      );
    }
    const rawOidcIssuer = process.env.OIDC_ISSUER_URL;
    if (!rawOidcIssuer || !rawOidcIssuer.trim()) {
      throw new Error(
        `FATAL: ${currentEnv.toUpperCase()} requires OIDC_ISSUER_URL to be configured. Hardcoded fallback secrets are forbidden.`
      );
    }
    const rawOidcClient = process.env.OIDC_CLIENT_ID;
    if (!rawOidcClient || !rawOidcClient.trim()) {
      throw new Error(
        `FATAL: ${currentEnv.toUpperCase()} requires OIDC_CLIENT_ID to be configured.`
      );
    }
  }
}

export const env = {
  port: toInt(process.env.PORT, 4000),
  nodeEnv: rawNodeEnv,
  isProduction,
  isStaging,
  isDeployedEnv,
  isDevelopment,
  allowDevAuth,
  corsOrigins: toList(process.env.CORS_ORIGINS).length > 0 
    ? toList(process.env.CORS_ORIGINS) 
    : ["http://localhost:5173", "http://localhost:3000"],
  databasePath: process.env.DATABASE_PATH ?? path.join(process.cwd(), "incognito.sqlite"),
  encryptionKey: process.env.ENCRYPTION_KEY ?? (isDeployedEnv ? "" : "dev-only-local-encryption-key-32b!"),
  authSecret: process.env.AUTH_SECRET ?? (isDeployedEnv ? "" : "dev-only-local-auth-secret-min-32-chars-key!"),
  authProvider: process.env.AUTH_PROVIDER ?? "jwt",
  oidcIssuerUrl: process.env.OIDC_ISSUER_URL ?? (isDeployedEnv ? "" : "https://login.microsoftonline.com/institutional-tenant/v2.0"),
  oidcClientId: process.env.OIDC_CLIENT_ID ?? (isDeployedEnv ? "" : "incognito-institutional-app-id"),
  oidcJwksUri: process.env.OIDC_JWKS_URI ?? "",
  oidcAllowedDomains: process.env.OIDC_ALLOWED_DOMAINS 
    ? toList(process.env.OIDC_ALLOWED_DOMAINS) 
    : ["university.edu", "campus.ac.in"],
  blockchainNetwork: process.env.BLOCKCHAIN_NETWORK ?? "Sepolia Testnet",
  contractAddress: process.env.CONTRACT_ADDRESS ?? "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  blockchainRpcUrl: process.env.BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8545",
  blockchainPrivateKey: process.env.BLOCKCHAIN_PRIVATE_KEY ?? "",
} as const;
