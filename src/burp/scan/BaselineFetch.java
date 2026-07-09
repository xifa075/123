package burp.scan;

/** Soft-404 baseline fetch result. */
public final class BaselineFetch {
    public final Object signature;
    public final boolean retryable;
    public final boolean budgetBlocked;

    public BaselineFetch(Object signature, boolean retryable, boolean budgetBlocked) {
        this.signature = signature;
        this.retryable = retryable;
        this.budgetBlocked = budgetBlocked;
    }

    public static BaselineFetch none() { return new BaselineFetch(null, false, false); }
    public static BaselineFetch retryable() { return new BaselineFetch(null, true, false); }
    public static BaselineFetch budget() { return new BaselineFetch(null, false, true); }
}
