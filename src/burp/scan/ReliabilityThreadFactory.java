package burp.scan;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/** Daemon thread factory for reliable scan workers. */
public final class ReliabilityThreadFactory implements ThreadFactory {
    private final AtomicInteger sequence = new AtomicInteger(1);

    public Thread newThread(Runnable runnable) {
        Thread thread = new Thread(runnable, "cgn-reliability-" + sequence.getAndIncrement());
        thread.setDaemon(true);
        thread.setUncaughtExceptionHandler((t, e) -> { /* worker catches task failures itself */ });
        return thread;
    }
}
