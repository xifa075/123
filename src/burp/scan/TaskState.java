package burp.scan;

/** Reliable scan task lifecycle. */
public enum TaskState {
    PENDING,
    RUNNING,
    SUCCESS,
    FAILED,
    RETRYABLE,
    CANCELLED
}
