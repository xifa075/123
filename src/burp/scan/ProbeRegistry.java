package burp.scan;

import burp.ScanResultRepository;

/** Owns in-flight/final probe deduplication so task execution code remains focused on scanning. */
public final class ProbeRegistry {
    private final ScanResultRepository repository;
    private final int maxCompletedKeys;

    public ProbeRegistry(ScanResultRepository repository, int maxCompletedKeys) {
        this.repository = repository;
        this.maxCompletedKeys = maxCompletedKeys;
    }

    public boolean claim(String key) {
        if (repository.completedProbeKeys().containsKey(key)) {
            return false;
        }
        return repository.inFlightProbeKeys().putIfAbsent(key, Boolean.TRUE) == null;
    }

    public void complete(String key) {
        repository.inFlightProbeKeys().remove(key);
        repository.completedProbeKeys().put(key, Boolean.TRUE);
        if (repository.completedProbeKeys().size() > maxCompletedKeys) {
            // Completed keys are cache-like. Clear only completed keys; never running keys.
            repository.completedProbeKeys().clear();
        }
    }

    public void release(String key) {
        repository.inFlightProbeKeys().remove(key);
    }
}
