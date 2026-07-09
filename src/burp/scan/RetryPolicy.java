package burp.scan;

import burp.config.ScanConfig;

/** Centralized retry/backoff policy used by scan tasks and active probes. */
public final class RetryPolicy {
    private RetryPolicy() { }

    public static boolean canRetry(int attempt, ScanConfig config) {
        if (config == null) return false;
        return attempt <= config.maxRetries;
    }

    public static long backoffMillis(ScanConfig config, int attempt) {
        if (config == null) return 500L;
        int safeAttempt = Math.max(1, attempt);
        long value = (long) config.retryInitialMillis * safeAttempt;
        return Math.max(ScanConfig.MIN_RETRY_DELAY_MS,
                Math.min(ScanConfig.MAX_RETRY_DELAY_MS, value));
    }
}
