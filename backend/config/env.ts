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

export const env = {
  port: toInt(process.env.PORT, 4000),
  nodeEnv: process.env.NODE_ENV ?? "development",
  corsOrigins: toList(process.env.CORS_ORIGINS).length > 0 
    ? toList(process.env.CORS_ORIGINS) 
    : ["http://localhost:5173", "http://localhost:3000"],
  databasePath: process.env.DATABASE_PATH ?? path.join(process.cwd(), "incognito.sqlite"),
  encryptionKey: process.env.ENCRYPTION_KEY ?? (process.env.NODE_ENV === "production" ? "" : "dev-only-local-encryption-key-32b!"),
  authSecret: process.env.AUTH_SECRET ?? (process.env.NODE_ENV === "production" ? "" : "dev-only-local-auth-secret-min-32-chars-key!"),
  authProvider: process.env.AUTH_PROVIDER ?? (process.env.NODE_ENV === "production" ? "jwt" : "jwt"),
  blockchainNetwork: process.env.BLOCKCHAIN_NETWORK ?? "Sepolia Testnet",
  contractAddress: process.env.CONTRACT_ADDRESS ?? "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  blockchainRpcUrl: process.env.BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8545",
  blockchainPrivateKey: process.env.BLOCKCHAIN_PRIVATE_KEY ?? "",
} as const;
