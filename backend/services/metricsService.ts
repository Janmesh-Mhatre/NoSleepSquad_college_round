export interface OperationalMetrics {
  totalRequests: number;
  providerCalls: {
    gemini: number;
    openai: number;
    blockchainRpc: number;
    oidc: number;
  };
  failureCounts: {
    gemini: number;
    openai: number;
    blockchainRpc: number;
    oidc: number;
  };
  retryCounts: number;
  averageLatencyMs: number;
}

export class MetricsService {
  private metrics: OperationalMetrics = {
    totalRequests: 0,
    providerCalls: {
      gemini: 0,
      openai: 0,
      blockchainRpc: 0,
      oidc: 0,
    },
    failureCounts: {
      gemini: 0,
      openai: 0,
      blockchainRpc: 0,
      oidc: 0,
    },
    retryCounts: 0,
    averageLatencyMs: 0,
  };

  private latencies: number[] = [];

  recordCall(provider: "gemini" | "openai" | "blockchainRpc" | "oidc", latencyMs: number) {
    this.metrics.totalRequests++;
    this.metrics.providerCalls[provider]++;
    this.latencies.push(latencyMs);
    if (this.latencies.length > 100) {
      this.latencies.shift();
    }
    const sum = this.latencies.reduce((a, b) => a + b, 0);
    this.metrics.averageLatencyMs = Math.round(sum / this.latencies.length);
  }

  recordFailure(provider: "gemini" | "openai" | "blockchainRpc" | "oidc") {
    this.metrics.failureCounts[provider]++;
  }

  recordRetry() {
    this.metrics.retryCounts++;
  }

  getSnapshot(): OperationalMetrics {
    return { ...this.metrics };
  }

  /**
   * Asserts that metrics output contains ZERO sensitive whistleblower data.
   */
  assertMetricsPrivacy(): boolean {
    const serialized = JSON.stringify(this.metrics);
    const forbidden = [/student/i, /report/i, /nullifier/i, /email/i, /key/i, /secret/i];
    for (const pat of forbidden) {
      if (pat.test(serialized)) {
        throw new Error(`PRIVACY VIOLATION in metrics: found pattern ${pat}`);
      }
    }
    return true;
  }
}

export const metricsService = new MetricsService();
