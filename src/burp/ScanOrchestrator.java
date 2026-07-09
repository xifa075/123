package burp;

import burp.config.ScanConfig;
import burp.config.UiScanSnapshot;
import burp.result.ScanResultViewModel;
import burp.scan.TaskRecord;

/** Public internal contract for scheduling; hides the legacy-compatible implementation core. */
public final class ScanOrchestrator {
    private final ScanOrchestratorCore core;
    public ScanOrchestrator(BurpExtender extender) { this(new ScanOrchestratorCore(extender)); }
    public ScanOrchestrator(ScanOrchestratorCore core) { this.core = core; }
    public void install(IBurpExtenderCallbacks callbacks) { core.install(callbacks); }
    public void shutdown() { core.shutdown(); }
    public void enqueueAutomatic(int toolFlag, IHttpRequestResponse message) { core.enqueueAutomatic(toolFlag, message); }
    public void enqueueManual(IHttpRequestResponse message) { core.enqueueManual(message); }
    public void retryFailed() { core.retryFailed(); }
    public void retryTask(String key) { core.retryTask(key); }
    public void setPaused(boolean paused) { core.setPaused(paused); }
    public boolean paused() { return core.paused(); }
    java.util.List<BurpViewModel.TaskView> taskViewsForUi() { return core.taskViewsForUi(); }
    public String contextMenuStatus() { return core.contextMenuStatus(); }
    public String normalizedHost(IHttpRequestResponse message) { return core.normalizedHost(message); }
    public boolean scopeRequired() { return core.scopeRequired(); }
    public ScanConfig config() { return core.config(); }
    java.util.Map<String, TaskRecord> taskRecordsForDiagnostics() {
        return core.taskRecordsForDiagnostics();
    }
    public UiScanSnapshot uiSnapshotForDiagnostics() { return core.uiSnapshotForDiagnostics(); }
    public ScanResultViewModel.ResultUiMetrics resultUiMetricsForDiagnostics() {
        return core.resultUiMetricsForDiagnostics();
    }
    public void requestResultViewRefresh(boolean filterChanged) { core.requestResultViewRefresh(filterChanged); }
}
