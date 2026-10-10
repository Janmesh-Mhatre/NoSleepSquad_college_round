export interface SecurityTestResult {
  id: string;
  name: string;
  category: "identity_separation" | "cryptographic_privacy" | "transport_security" | "access_control";
  status: "passed" | "warning" | "failed";
  details: string;
  durationMs: number;
  testedAt: string;
}

export interface SecurityPostureSummary {
  overallStatus: "healthy" | "advisory" | "critical";
  lastScanTimestamp: string;
  testsPassed: number;
  testsTotal: number;
  results: SecurityTestResult[];
  securityAdvisories: string[];
}
