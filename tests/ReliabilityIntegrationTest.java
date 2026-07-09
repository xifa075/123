package burp;
import burp.scan.*;

import burp.*;
import burp.bootstrap.*;
import burp.config.*;
import burp.dictionary.*;
import burp.fingerprint.*;
import burp.js.*;
import burp.request.*;
import burp.result.*;
import burp.traffic.*;

import java.awt.Component;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

public final class ReliabilityIntegrationTest {
    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless", "true");
        Path work = Files.createTempDirectory("cgn-reliability-it");
        System.setProperty("user.dir", work.toString());
        Files.writeString(work.resolve("cgn_reliability.properties"),
                "source.target=true\nsource.proxy=true\nsource.repeater=true\nsource.intruder=true\nsource.scanner=true\nscope.required=true\nretry.max=2\nretry.initial.ms=200\nqueue.pending.limit=50\n", StandardCharsets.UTF_8);
        String layeredTestConfig = "version=1\ncount=1\n"
                + "group.0.id=test-layered\n"
                + "group.0.name=Integration Test Dictionary\n"
                + "group.0.enabled=true\n"
                + "group.0.minLevel=0\n"
                + "group.0.maxLevel=4\n"
                + "group.0.strategy=CURRENT\n"
                + "group.0.templateName=\n"
                + "group.0.priority=10\n"
                + "group.0.maxRequests=10\n"
                + "group.0.entries=health\n";
        Files.writeString(work.resolve("cgn_layered_dictionaries.properties"), layeredTestConfig, StandardCharsets.UTF_8);
        Files.writeString(Path.of("cgn_layered_dictionaries.properties"), layeredTestConfig, StandardCharsets.UTF_8);

        assertArchitectureModules();
        assertFingerprintEngine();
        assertTemplateSafetyPolicy();

        MockCallbacks callbacks = new MockCallbacks();
        BurpExtender extender = new BurpExtender();
        extender.registerExtenderCallbacks(callbacks);
        Thread.sleep(600L);
        // Keep the integration test bounded: retain the legacy UI but use one explicit test path.
        if (extender.jp_host_uri_scan_diy_uri == null) {
            throw new AssertionError("UI did not initialize");
        }
        SwingUtilities.invokeAndWait(() -> {
            extender.jp_host_uri_scan_diy_uri.setText("/health");
            extender.jp_host_uri_scan_2_jb.setSelected(true);
            extender.jp_host_uri_scan_2_tf.setText("50");
            extender.switchs.setSelected(true);
            try { clearBuiltInPaths(extender); }
            catch (Exception error) { throw new RuntimeException(error); }
        });
        // The runtime snapshot is published after the EDT has finished processing this edit batch.
        Thread.sleep(300L);
        UiScanSnapshot uiSnapshot = uiSnapshot(extender);
        if (!uiSnapshot.pluginEnabled || !uiSnapshot.directoryScanEnabled
                || !uiSnapshot.ruleSnapshot.pathEntries().contains("/health")) {
            throw new AssertionError("EDT snapshot did not contain the edited legacy UI values");
        }

        MockService service = new MockService("example.test", 80, "http");
        MockMessage seed = new MockMessage(service,
                "GET /app/item?id=1 HTTP/1.1\r\nHost: example.test\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1),
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nseed".getBytes(StandardCharsets.ISO_8859_1));

        // Repeater is explicitly configured as a source. The first generated request has no
        // response, forcing a RETRYABLE path; later responses are valid and must complete.
        extender.processHttpMessage(64, false, seed);
        Thread.sleep(2200L);
        if (callbacks.requestCount.get() < 3) {
            throw new AssertionError("Expected retry/baseline/generated requests, got " + callbacks.requestCount.get());
        }
        if (!hasSuccessfulTask(extender)) {
            System.out.println("states=" + taskStates(extender));
            throw new AssertionError("Expected a SUCCESS task state after retry completion");
        }
        int beforeOutOfScope = callbacks.requestCount.get();
        MockService outsideService = new MockService("outside.test", 80, "http");
        MockMessage outside = new MockMessage(outsideService,
                "GET /x HTTP/1.1\r\nHost: outside.test\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1),
                "HTTP/1.1 200 OK\r\n\r\noutside".getBytes(StandardCharsets.ISO_8859_1));
        extender.processHttpMessage(64, false, outside);
        Thread.sleep(350L);
        if (callbacks.requestCount.get() != beforeOutOfScope) {
            throw new AssertionError("Out-of-scope response should not create probes");
        }

        int beforeActive = callbacks.requestCount.get();
        List<IScanIssue> active = extender.doActiveScan(seed, new SimpleInsertionPoint(seed.getRequest(), "id"));
        int afterFirstActive = callbacks.requestCount.get();
        extender.doActiveScan(seed, new SimpleInsertionPoint(seed.getRequest(), "id"));
        int afterSecondActive = callbacks.requestCount.get();
        if (afterFirstActive <= beforeActive) {
            throw new AssertionError("Active verification did not send a safe probe");
        }
        if (afterSecondActive != afterFirstActive) {
            throw new AssertionError("Completed active probe was not deduplicated");
        }
        if (active == null || active.isEmpty()) {
            throw new AssertionError("Expected active reflection evidence issue");
        }
        callbacks.forcedNullResponses.set(1);
        int beforeFlakyActive = callbacks.requestCount.get();
        List<IScanIssue> flakyActive = extender.doActiveScan(seed, new SimpleInsertionPoint(seed.getRequest(), "flaky"));
        int afterFlakyActive = callbacks.requestCount.get();
        if (afterFlakyActive - beforeFlakyActive < 2 || flakyActive == null || flakyActive.isEmpty()) {
            throw new AssertionError("Expected active network retry and eventual evidence issue");
        }
        extender.doActiveScan(seed, new SimpleInsertionPoint(seed.getRequest(), "flaky"));
        if (callbacks.requestCount.get() != afterFlakyActive) {
            throw new AssertionError("Successful retried active probe was not committed to final dedup");
        }

        assertIndexedResultProjection(extender, seed);
        assertScanWorkbenchUi(extender);
        assertConfigurationWorkflowUi(extender);
        assertLayeredDictionaryUiAndStore(extender);

        extender.extensionUnloaded();
        System.out.println("reliability-integration-ok requests=" + callbacks.requestCount.get());
    }

    private static void assertIndexedResultProjection(BurpExtender extender, MockMessage seed) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            extender.Hosts = "example.test";
            extender.jp_host_uri_scan_3_jb.setSelected(true);
            extender.jp_host_uri_scan_3_jb2.setSelected(true);
            extender.jp_host_uri_scan_3_jb3.setSelected(true);
            extender.jp_host_uri_scan_3_jb4.setSelected(true);
            extender.jp_host_uri_scan_3_jb5.setSelected(true);
            extender.jp_host_uri_scan_3_jb6.setSelected(true);
            extender.jp_host_uri_scan_3_jb7.setSelected(true);
            extender.jp_host_uri_scan_3_jb8.setSelected(true);
        });
        BurpViewModel view = viewModel(extender);
        ScanResultViewModel.ResultUiMetrics before = resultMetrics(extender);
        Constructor<?> ctor = Class.forName("burp.BurpExtender$LogEntry").getDeclaredConstructor(
                String.class, IHttpRequestResponsePersisted.class, String.class, String.class,
                String.class, String.class, int.class, int.class);
        ctor.setAccessible(true);
        for (int i = 0; i < 650; i++) {
            Object entry = ctor.newInstance("GET", seed, "http://example.test/indexed/" + i,
                    "indexed", "Information", "projection", 10 + i, 200);
            BurpExtensionAccess.invokePrivate(extender, "addScanLogEntry",
                    new Class<?>[] { ctor.getDeclaringClass() }, new Object[] { entry });
            view.onScanLogEntryAdded(entry);
        }
        Thread.sleep(900L); // 350ms result coalescer plus EDT scheduling margin.
        ScanResultViewModel.ResultUiMetrics after = resultMetrics(extender);
        if (after.indexedEntries < 650 || after.matchedEntries < 650) {
            throw new AssertionError("Result index did not receive appended log entries: "
                    + after.indexedEntries + "/" + after.matchedEntries);
        }
        if (after.displayedEntries > ScanResultViewModel.DEFAULT_PAGE_SIZE) {
            throw new AssertionError("Result projection ignored page cap: " + after.displayedEntries);
        }
        if (after.fullIndexRebuilds != before.fullIndexRebuilds) {
            throw new AssertionError("Appending results should not rebuild the full log index");
        }
        if (after.incrementalFlushes <= before.incrementalFlushes) {
            throw new AssertionError("Expected coalesced incremental result refresh");
        }

        SwingUtilities.invokeAndWait(() -> extender.jp_host_uri_scan_3_jb.setSelected(false));
        CgnEnhancement.scanUriFilter(extender);
        Thread.sleep(250L);
        ScanResultViewModel.ResultUiMetrics filtered = resultMetrics(extender);
        if (filtered.matchedEntries != 0) {
            throw new AssertionError("Status filter was not served from indexed projection");
        }
        SwingUtilities.invokeAndWait(() -> extender.jp_host_uri_scan_3_jb.setSelected(true));
        CgnEnhancement.scanUriFilter(extender);
        Thread.sleep(250L);
    }

    private static void assertScanWorkbenchUi(BurpExtender extender) throws Exception {
        Field tabsField = BurpExtender.class.getDeclaredField("mainTabs");
        tabsField.setAccessible(true);
        javax.swing.JTabbedPane tabs = (javax.swing.JTabbedPane) tabsField.get(extender);
        if (tabs == null) throw new AssertionError("Main tabs were not initialized");
        int workbench = -1;
        for (int i = 0; i < tabs.getTabCount(); i++) {
            if ("扫描控制台".equals(tabs.getTitleAt(i))) { workbench = i; break; }
        }
        if (workbench < 0) throw new AssertionError("Scan workbench tab was not installed");
        final int selected = workbench;
        SwingUtilities.invokeAndWait(() -> tabs.setSelectedIndex(selected));

        ScanOrchestrator orchestrator = orchestrator(extender);
        orchestrator.setPaused(true);
        Thread.sleep(150L);
        if (!orchestrator.paused()) throw new AssertionError("Workbench pause command was not applied");
        orchestrator.setPaused(false);
        Thread.sleep(150L);
        if (orchestrator.paused()) throw new AssertionError("Workbench resume command was not applied");
    }

    private static void assertTemplateSafetyPolicy() throws Exception {
        Class<?> groupType = Class.forName("burp.BurpExtender$RequestGroup");
        Constructor<?> ctor = groupType.getDeclaredConstructor(String.class, String.class, String.class,
                String.class, String.class, String.class, boolean.class,
                boolean.class, boolean.class, boolean.class, boolean.class, boolean.class);
        ctor.setAccessible(true);
        Object post = ctor.newInstance("write", "POST", "/mutate", "x=1", "", "", true,
                true, false, false, false, false);
        Object get = ctor.newInstance("read", "GET", "/health", "", "", "", true,
                true, false, false, false, false);
        RequestBuilder builder = new RequestBuilder(null);
        ScanConfig safe = ScanConfig.defaults();
        if (builder.isMethodAllowed(post, safe)) {
            throw new AssertionError("POST template must be blocked by default");
        }
        if (!builder.isMethodAllowed(get, safe)) {
            throw new AssertionError("GET template must remain enabled by default");
        }
        if (!builder.isMethodAllowed(post, safe.withUnsafeTemplateMethodsAllowed(true))) {
            throw new AssertionError("Explicit confirmation must allow POST template");
        }
    }

    private static void assertConfigurationWorkflowUi(BurpExtender extender) throws Exception {
        Field tabsField = BurpExtender.class.getDeclaredField("configurationTabs");
        tabsField.setAccessible(true);
        javax.swing.JTabbedPane tabs = (javax.swing.JTabbedPane) tabsField.get(extender);
        if (tabs == null) throw new AssertionError("Configuration tabs were not initialized");
        int workflow = -1;
        for (int i = 0; i < tabs.getTabCount(); i++) {
            if ("配置向导".equals(tabs.getTitleAt(i))) { workflow = i; break; }
        }
        if (workflow < 0) throw new AssertionError("Configuration workflow tab was not installed");
        final int selected = workflow;
        SwingUtilities.invokeAndWait(() -> tabs.setSelectedIndex(selected));
        ScanOrchestrator orchestrator = orchestrator(extender);
        Field core = ScanOrchestrator.class.getDeclaredField("core");
        core.setAccessible(true);
        ScanOrchestratorCore coreValue = (ScanOrchestratorCore) core.get(orchestrator);
        if (coreValue.config().unsafeTemplateMethodsAllowed) {
            throw new AssertionError("Write-method templates must remain blocked by default");
        }
    }


    private static void assertLayeredDictionaryUiAndStore(BurpExtender extender) throws Exception {
        Field tabsField = BurpExtender.class.getDeclaredField("configurationTabs");
        tabsField.setAccessible(true);
        javax.swing.JTabbedPane tabs = (javax.swing.JTabbedPane) tabsField.get(extender);
        if (tabs == null) throw new AssertionError("Configuration tabs were not initialized");
        int layered = -1;
        for (int i = 0; i < tabs.getTabCount(); i++) {
            if ("分层字典".equals(tabs.getTitleAt(i))) { layered = i; break; }
        }
        if (layered < 0) throw new AssertionError("Layered dictionary tab was not installed");

        Files.deleteIfExists(Path.of("cgn_layered_dictionaries.properties"));
        LayeredDictionaryStore store = new LayeredDictionaryStore();
        List<LayeredDictionaryStore.DictionaryGroup> fallback = store.load(Arrays.asList("admin", "api"));
        if (fallback.size() < 12) {
            throw new AssertionError("Built-in layered dictionary presets were not materialized");
        }
        boolean rootPreset = false;
        boolean legacyMigrated = false;
        for (LayeredDictionaryStore.DictionaryGroup group : fallback) {
            if ("preset-01".equals(group.id) && group.entries.contains("swagger-ui")) rootPreset = true;
            if ("legacy-default".equals(group.id) && group.entries.contains("admin")) legacyMigrated = true;
        }
        if (!rootPreset || !legacyMigrated) {
            throw new AssertionError("Preset dictionary groups or migrated legacy group are missing");
        }
        LayeredDictionaryStore.DictionaryGroup root = new LayeredDictionaryStore.DictionaryGroup(
                "root-test", "Root Entries", true, 1, 1, LayeredDictionaryStore.PathStrategy.ROOT,
                "", 10, 5, Arrays.asList("admin", "login"), false);
        store.save(Arrays.asList(root));
        List<LayeredDictionaryStore.DictionaryGroup> configured = store.load(Arrays.asList("legacy-only"));
        if (configured.size() != 1 || configured.get(0).legacyFallback || configured.get(0).minLevel != 1
                || configured.get(0).maxLevel != 1 || configured.get(0).strategy != LayeredDictionaryStore.PathStrategy.ROOT) {
            throw new AssertionError("Configured layered dictionary group was not loaded correctly");
        }
    }

    private static ScanOrchestrator orchestrator(BurpExtender extender) throws Exception {
        Field all = CgnReliability.class.getDeclaredField("ORCHESTRATORS");
        all.setAccessible(true);
        java.util.Map<?, ?> map = (java.util.Map<?, ?>) all.get(null);
        ScanOrchestrator orchestrator = (ScanOrchestrator) map.get(extender);
        if (orchestrator == null) throw new AssertionError("Missing orchestrator");
        return orchestrator;
    }

    private static BurpViewModel viewModel(BurpExtender extender) throws Exception {
        Field all = CgnReliability.class.getDeclaredField("ORCHESTRATORS");
        all.setAccessible(true);
        java.util.Map<?, ?> map = (java.util.Map<?, ?>) all.get(null);
        ScanOrchestrator orchestrator = (ScanOrchestrator) map.get(extender);
        Field core = ScanOrchestrator.class.getDeclaredField("core");
        core.setAccessible(true);
        Object coreValue = core.get(orchestrator);
        Field view = ScanOrchestratorCore.class.getDeclaredField("viewModel");
        view.setAccessible(true);
        return (BurpViewModel) view.get(coreValue);
    }

    private static ScanResultViewModel.ResultUiMetrics resultMetrics(BurpExtender extender)
            throws Exception {
        Field all = CgnReliability.class.getDeclaredField("ORCHESTRATORS");
        all.setAccessible(true);
        java.util.Map<?, ?> map = (java.util.Map<?, ?>) all.get(null);
        ScanOrchestrator orchestrator = (ScanOrchestrator) map.get(extender);
        if (orchestrator == null) throw new AssertionError("Missing orchestrator");
        final ScanResultViewModel.ResultUiMetrics[] result = new ScanResultViewModel.ResultUiMetrics[1];
        SwingUtilities.invokeAndWait(() -> result[0] = orchestrator.resultUiMetricsForDiagnostics());
        return result[0];
    }

    private static String taskStates(BurpExtender extender) throws Exception {
        StringBuilder out = new StringBuilder();
        for (TaskRecord record : taskRecords(extender).values()) {
            out.append(record.state).append(":").append(record.message).append("; ");
        }
        return out.toString();
    }

    private static boolean hasSuccessfulTask(BurpExtender extender) throws Exception {
        for (TaskRecord record : taskRecords(extender).values()) {
            if (record.state == TaskState.SUCCESS) return true;
        }
        return false;
    }

    private static UiScanSnapshot uiSnapshot(BurpExtender extender) throws Exception {
        java.lang.reflect.Field all = CgnReliability.class.getDeclaredField("ORCHESTRATORS");
        all.setAccessible(true);
        java.util.Map<?, ?> map = (java.util.Map<?, ?>) all.get(null);
        ScanOrchestrator orchestrator = (ScanOrchestrator) map.get(extender);
        if (orchestrator == null) throw new AssertionError("Missing orchestrator");
        return orchestrator.uiSnapshotForDiagnostics();
    }

    @SuppressWarnings("unchecked")
    private static java.util.Map<String, TaskRecord> taskRecords(BurpExtender extender)
            throws Exception {
        java.lang.reflect.Field all = CgnReliability.class.getDeclaredField("ORCHESTRATORS");
        all.setAccessible(true);
        java.util.Map<?, ?> map = (java.util.Map<?, ?>) all.get(null);
        ScanOrchestrator orchestrator = (ScanOrchestrator) map.get(extender);
        if (orchestrator == null) throw new AssertionError("Missing orchestrator");
        return orchestrator.taskRecordsForDiagnostics();
    }

    private static void assertArchitectureModules() throws Exception {
        String[] modules = {
                "burp.bootstrap.ExtensionBootstrap", "burp.traffic.BurpTrafficListener", "burp.ScanOrchestrator",
                "burp.request.RequestBuilder", "burp.fingerprint.FingerprintEngine", "burp.js.JsExtractionEngine",
                "burp.dictionary.LayeredDictionaryStore", "burp.result.ScanResultViewModel",
                "burp.scan.RetryPolicy", "burp.scan.ScopeGuard",
                "burp.RuleLibraryRepository", "burp.ScanResultRepository",
                "burp.config.ScanConfig", "burp.BurpViewModel"
        };
        for (String module : modules) Class.forName(module);
        ScanConfig defaults = ScanConfig.defaults();
        ScanConfig changed = defaults.withRetries(1).withPendingLimit(75);
        if (defaults == changed || defaults.maxRetries != 2 || changed.maxRetries != 1
                || changed.pendingLimit != 75) {
            throw new AssertionError("ScanConfig must remain immutable");
        }
    }

    private static void assertFingerprintEngine() {
        String evidence = "/admin\nServer: nginx\n<html>Jenkins dashboard</html>";
        if (!FingerprintEngine.matches(evidence, "url:/admin|body:jenkins|!body:disabled")) {
            throw new AssertionError("Expected scoped AND fingerprint match");
        }
        if (!FingerprintEngine.matches(evidence, "header:apache || body:jenkins")) {
            throw new AssertionError("Expected OR fingerprint match");
        }
        if (FingerprintEngine.matches(evidence, "body:spark")) {
            throw new AssertionError("Word-boundary fingerprint should not match unrelated content");
        }
    }

    private static void clearBuiltInPaths(BurpExtender extender) throws Exception {
        java.lang.reflect.Field storeField = BurpExtender.class.getDeclaredField("ruleLibraryStore");
        storeField.setAccessible(true);
        Object store = storeField.get(extender);
        java.lang.reflect.Field builtIns = store.getClass().getDeclaredField("builtInLibraries");
        builtIns.setAccessible(true);
        ((List<?>) builtIns.get(store)).clear();
    }

    public static final class MockCallbacks implements IBurpExtenderCallbacks {
        final AtomicInteger requestCount = new AtomicInteger();
        final AtomicInteger forcedNullResponses = new AtomicInteger();
        final MockHelpers helpers = new MockHelpers();
        final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        public boolean isInScope(URL url) { return url != null && "example.test".equals(url.getHost()); }
        public OutputStream getStdout() { return stdout; }
        public IExtensionHelpers getHelpers() { return helpers; }
        public void setExtensionName(String name) { }
        public void registerExtensionStateListener(IExtensionStateListener listener) { }
        public IMessageEditor createMessageEditor(IMessageEditorController controller, boolean editable) { return new MockEditor(); }
        public void customizeUiComponent(Component component) { }
        public void addSuiteTab(ITab tab) { }
        public void registerHttpListener(IHttpListener listener) { }
        public void registerScannerCheck(IScannerCheck check) { }
        public IHttpRequestResponse makeHttpRequest(IHttpService service, byte[] request) {
            int n = requestCount.incrementAndGet();
            if (n == 1 || forcedNullResponses.getAndUpdate(value -> Math.max(0, value - 1)) > 0) {
                return new MockMessage(service, request, null);
            }
            String body = new String(request, StandardCharsets.ISO_8859_1);
            String response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body;
            return new MockMessage(service, request, response.getBytes(StandardCharsets.ISO_8859_1));
        }
        public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse requestResponse) {
            if (requestResponse instanceof IHttpRequestResponsePersisted) {
                return (IHttpRequestResponsePersisted) requestResponse;
            }
            return new MockMessage(requestResponse.getHttpService(), requestResponse.getRequest(), requestResponse.getResponse());
        }
    }

    static final class MockEditor implements IMessageEditor {
        public Component getComponent() { return new JPanel(); }
        public void setMessage(byte[] message, boolean isRequest) { }
    }

    static final class MockService implements IHttpService {
        final String host; final int port; final String protocol;
        MockService(String host, int port, String protocol) { this.host = host; this.port = port; this.protocol = protocol; }
        public String getHost() { return host; }
        public int getPort() { return port; }
        public String getProtocol() { return protocol; }
    }

    static final class MockMessage implements IHttpRequestResponsePersisted {
        final IHttpService service; final byte[] request; final byte[] response;
        MockMessage(IHttpService service, byte[] request, byte[] response) { this.service = service; this.request = request; this.response = response; }
        public byte[] getRequest() { return request; }
        public byte[] getResponse() { return response; }
        public IHttpService getHttpService() { return service; }
    }

    static final class MockRequestInfo implements IRequestInfo {
        final URL url; final List<String> headers; final String method;
        MockRequestInfo(URL url, List<String> headers, String method) { this.url = url; this.headers = headers; this.method = method; }
        public URL getUrl() { return url; }
        public List<String> getHeaders() { return headers; }
        public String getMethod() { return method; }
    }

    static final class MockResponseInfo implements IResponseInfo {
        final short status; final int bodyOffset; final List<String> headers;
        MockResponseInfo(short status, int bodyOffset, List<String> headers) { this.status = status; this.bodyOffset = bodyOffset; this.headers = headers; }
        public short getStatusCode() { return status; }
        public int getBodyOffset() { return bodyOffset; }
        public List<String> getHeaders() { return headers; }
    }

    static final class MockHelpers implements IExtensionHelpers {
        public IRequestInfo analyzeRequest(IHttpRequestResponse message) { return analyze(message.getHttpService(), message.getRequest()); }
        public IRequestInfo analyzeRequest(IHttpService service, byte[] request) { return analyze(service, request); }
        public IRequestInfo analyzeRequest(byte[] request) { return analyze(new MockService("example.test", 80, "http"), request); }
        private IRequestInfo analyze(IHttpService service, byte[] bytes) {
            String raw = new String(bytes == null ? new byte[0] : bytes, StandardCharsets.ISO_8859_1);
            String[] lines = raw.split("\\r?\\n");
            String first = lines.length == 0 ? "GET / HTTP/1.1" : lines[0];
            String[] parts = first.split(" ");
            String method = parts.length > 0 ? parts[0] : "GET";
            String target = parts.length > 1 ? parts[1] : "/";
            try {
                URL url = target.startsWith("http") ? new URL(target) : new URL(service.getProtocol(), service.getHost(), service.getPort(), target);
                return new MockRequestInfo(url, Arrays.asList(lines), method);
            } catch (Exception e) { throw new IllegalArgumentException(e); }
        }
        public IResponseInfo analyzeResponse(byte[] response) {
            String raw = new String(response == null ? new byte[0] : response, StandardCharsets.ISO_8859_1);
            int marker = raw.indexOf("\r\n\r\n");
            if (marker < 0) marker = raw.indexOf("\n\n");
            int offset = marker < 0 ? raw.length() : marker + (raw.startsWith("\r\n", Math.max(0, marker)) ? 4 : 2);
            String[] lines = raw.split("\\r?\\n");
            short status = 0;
            if (lines.length > 0) {
                String[] parts = lines[0].split(" ");
                if (parts.length > 1) status = Short.parseShort(parts[1]);
            }
            return new MockResponseInfo(status, offset, Arrays.asList(lines));
        }
        public byte[] buildHttpMessage(List<String> headers, byte[] body) {
            StringBuilder out = new StringBuilder();
            for (String h : headers) out.append(h).append("\r\n");
            out.append("\r\n");
            byte[] head = out.toString().getBytes(StandardCharsets.ISO_8859_1);
            byte[] tail = body == null ? new byte[0] : body;
            byte[] all = Arrays.copyOf(head, head.length + tail.length);
            System.arraycopy(tail, 0, all, head.length, tail.length);
            return all;
        }
        public String bytesToString(byte[] bytes) { return new String(bytes == null ? new byte[0] : bytes, StandardCharsets.ISO_8859_1); }
        public byte[] stringToBytes(String text) { return text == null ? new byte[0] : text.getBytes(StandardCharsets.ISO_8859_1); }
    }

    public static final class SimpleInsertionPoint implements IScannerInsertionPoint {
        final byte[] base; final String name;
        SimpleInsertionPoint(byte[] base, String name) { this.base = base; this.name = name; }
        public byte[] buildRequest(byte[] payload) {
            String source = new String(base, StandardCharsets.ISO_8859_1);
            return source.replace("id=1", "id=" + new String(payload, StandardCharsets.US_ASCII)).getBytes(StandardCharsets.ISO_8859_1);
        }
        public String getInsertionPointName() { return name; }
    }
}
