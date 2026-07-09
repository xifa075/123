package burp.scan;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Mutable task record owned by the scan repository. */
public final class TaskRecord {
    public final String key;
    public final ScanPlan plan;
    public final long createdAt = System.currentTimeMillis();
    public final AtomicBoolean scheduled = new AtomicBoolean(false);
    public final AtomicBoolean deferred = new AtomicBoolean(false);
    public final AtomicInteger attempts = new AtomicInteger(0);
    public volatile TaskState state = TaskState.PENDING;
    public volatile long updatedAt = createdAt;
    public volatile String message = "Queued";

    public TaskRecord(String key, ScanPlan plan) {
        this.key = key;
        this.plan = plan;
    }

    public synchronized void update(TaskState newState, String newMessage) {
        this.state = newState;
        this.message = newMessage == null ? "" : newMessage;
        this.updatedAt = System.currentTimeMillis();
    }
}
