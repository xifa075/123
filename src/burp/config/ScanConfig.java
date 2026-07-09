package burp.config;

import burp.scan.ScanSource;

/** Immutable runtime configuration snapshot consumed by worker threads. */
public final class ScanConfig {
    public static final int MIN_PENDING_LIMIT = 50;
    public static final int MAX_PENDING_LIMIT = 1000;
    public static final int MIN_RETRY_DELAY_MS = 200;
    public static final int MAX_RETRY_DELAY_MS = 5000;
    public static final int MAX_RETRIES = 2;

    public final boolean targetEnabled;
    public final boolean proxyEnabled;
    public final boolean scannerEnabled;
    public final boolean intruderEnabled;
    public final boolean repeaterEnabled;
    public final boolean scopeRequired;
    /** Explicit opt-in for POST / PUT / PATCH / DELETE request templates. */
    public final boolean unsafeTemplateMethodsAllowed;
    public final int maxRetries;
    public final int retryInitialMillis;
    public final int pendingLimit;

    public ScanConfig(boolean targetEnabled, boolean proxyEnabled, boolean scannerEnabled,
               boolean intruderEnabled, boolean repeaterEnabled, boolean scopeRequired,
               boolean unsafeTemplateMethodsAllowed, int maxRetries, int retryInitialMillis,
               int pendingLimit) {
        this.targetEnabled = targetEnabled;
        this.proxyEnabled = proxyEnabled;
        this.scannerEnabled = scannerEnabled;
        this.intruderEnabled = intruderEnabled;
        this.repeaterEnabled = repeaterEnabled;
        this.scopeRequired = scopeRequired;
        this.unsafeTemplateMethodsAllowed = unsafeTemplateMethodsAllowed;
        this.maxRetries = clamp(maxRetries, 0, MAX_RETRIES);
        this.retryInitialMillis = clamp(retryInitialMillis, MIN_RETRY_DELAY_MS, MAX_RETRY_DELAY_MS);
        this.pendingLimit = clamp(pendingLimit, MIN_PENDING_LIMIT, MAX_PENDING_LIMIT);
    }

    public static ScanConfig defaults() {
        // Safe-by-default: Scope enforced, normal browsing sources only, write methods blocked.
        return new ScanConfig(true, true, false, false, true, true, false, 2, 500, 500);
    }

    public boolean enabled(ScanSource source) {
        if (source == null) return false;
        switch (source) {
            case TARGET: return targetEnabled;
            case PROXY: return proxyEnabled;
            case SCANNER: return scannerEnabled;
            case INTRUDER: return intruderEnabled;
            case REPEATER: return repeaterEnabled;
            case MANUAL: return true;
            default: return false;
        }
    }

    public ScanConfig withSource(ScanSource source, boolean enabled) {
        if (source == null) return this;
        switch (source) {
            case TARGET: return copy(enabled, proxyEnabled, scannerEnabled, intruderEnabled, repeaterEnabled,
                    scopeRequired, unsafeTemplateMethodsAllowed, maxRetries, retryInitialMillis, pendingLimit);
            case PROXY: return copy(targetEnabled, enabled, scannerEnabled, intruderEnabled, repeaterEnabled,
                    scopeRequired, unsafeTemplateMethodsAllowed, maxRetries, retryInitialMillis, pendingLimit);
            case SCANNER: return copy(targetEnabled, proxyEnabled, enabled, intruderEnabled, repeaterEnabled,
                    scopeRequired, unsafeTemplateMethodsAllowed, maxRetries, retryInitialMillis, pendingLimit);
            case INTRUDER: return copy(targetEnabled, proxyEnabled, scannerEnabled, enabled, repeaterEnabled,
                    scopeRequired, unsafeTemplateMethodsAllowed, maxRetries, retryInitialMillis, pendingLimit);
            case REPEATER: return copy(targetEnabled, proxyEnabled, scannerEnabled, intruderEnabled, enabled,
                    scopeRequired, unsafeTemplateMethodsAllowed, maxRetries, retryInitialMillis, pendingLimit);
            default: return this;
        }
    }

    public ScanConfig withScopeRequired(boolean enabled) {
        return copy(targetEnabled, proxyEnabled, scannerEnabled, intruderEnabled, repeaterEnabled, enabled,
                unsafeTemplateMethodsAllowed, maxRetries, retryInitialMillis, pendingLimit);
    }

    public ScanConfig withUnsafeTemplateMethodsAllowed(boolean enabled) {
        return copy(targetEnabled, proxyEnabled, scannerEnabled, intruderEnabled, repeaterEnabled, scopeRequired,
                enabled, maxRetries, retryInitialMillis, pendingLimit);
    }

    public ScanConfig withRetries(int value) {
        return copy(targetEnabled, proxyEnabled, scannerEnabled, intruderEnabled, repeaterEnabled, scopeRequired,
                unsafeTemplateMethodsAllowed, value, retryInitialMillis, pendingLimit);
    }

    public ScanConfig withPendingLimit(int value) {
        return copy(targetEnabled, proxyEnabled, scannerEnabled, intruderEnabled, repeaterEnabled, scopeRequired,
                unsafeTemplateMethodsAllowed, maxRetries, retryInitialMillis, value);
    }

    private static ScanConfig copy(boolean targetEnabled, boolean proxyEnabled, boolean scannerEnabled,
                                   boolean intruderEnabled, boolean repeaterEnabled, boolean scopeRequired,
                                   boolean unsafeTemplateMethodsAllowed, int maxRetries,
                                   int retryInitialMillis, int pendingLimit) {
        return new ScanConfig(targetEnabled, proxyEnabled, scannerEnabled, intruderEnabled, repeaterEnabled,
                scopeRequired, unsafeTemplateMethodsAllowed, maxRetries, retryInitialMillis, pendingLimit);
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}
