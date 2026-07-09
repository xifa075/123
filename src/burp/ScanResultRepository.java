package burp;

import burp.scan.TaskRecord;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** Holds task state and scan result indexes; worker code never owns static global maps. */
public final class ScanResultRepository {
    private final ConcurrentMap<String, TaskRecord> records =
            new ConcurrentHashMap<String, TaskRecord>();
    private final ConcurrentMap<String, Boolean> inFlightProbeKeys =
            new ConcurrentHashMap<String, Boolean>();
    private final ConcurrentMap<String, Boolean> completedProbeKeys =
            new ConcurrentHashMap<String, Boolean>();

    public ConcurrentMap<String, TaskRecord> records() { return records; }
    public ConcurrentMap<String, Boolean> inFlightProbeKeys() { return inFlightProbeKeys; }
    public ConcurrentMap<String, Boolean> completedProbeKeys() { return completedProbeKeys; }

    public void clearSessionState() {
        inFlightProbeKeys.clear();
    }
}
