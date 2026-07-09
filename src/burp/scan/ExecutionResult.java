package burp.scan;

/** Result of one reliable scan task execution attempt. */
public final class ExecutionResult {
    public final boolean retryable;
    public final boolean cancelled;
    public final boolean budgetBlocked;
    public final String detail;

    private ExecutionResult(boolean retryable, boolean cancelled, boolean budgetBlocked, String detail) {
        this.retryable = retryable;
        this.cancelled = cancelled;
        this.budgetBlocked = budgetBlocked;
        this.detail = detail == null ? "" : detail;
    }

    public static ExecutionResult success(String detail) {
        return new ExecutionResult(false, false, false, detail);
    }

    public static ExecutionResult retryable(String detail) {
        return new ExecutionResult(true, false, false, detail);
    }

    public static ExecutionResult cancelled(String detail) {
        return new ExecutionResult(false, true, false, detail);
    }

    public static ExecutionResult budget(String detail) {
        return new ExecutionResult(false, false, true, detail);
    }
}
