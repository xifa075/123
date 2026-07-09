package burp;

import burp.config.ScanConfig;
import burp.config.ScanConfigStore;
import burp.config.UiScanSnapshot;
import burp.dictionary.LayeredDictionaryStore;
import burp.js.JsExtractionEngine;
import burp.request.RequestBuilder;
import burp.result.ScanResultViewModel;
import burp.scan.BaselineFetch;
import burp.scan.ExecutionResult;
import burp.scan.ProbeRegistry;
import burp.scan.ReliabilityThreadFactory;
import burp.scan.ScanPathPlanner;
import burp.scan.ScanPlan;
import burp.scan.ScanSource;
import burp.scan.TaskRecord;
import burp.scan.TaskState;

import static burp.CgnReliability.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Worker-side scheduler. It depends only on immutable ScanConfig and explicit adapters. */
public final class ScanOrchestratorCore {
    private final BurpExtender extender;
    private final ScanResultRepository resultRepository = new ScanResultRepository();
    private final ProbeRegistry probeRegistry = new ProbeRegistry(resultRepository, HARD_MAX_COMPLETED_KEYS);
    private final RuleLibraryRepository ruleLibraryRepository;
    private final RequestBuilder requestBuilder;
    private final JsExtractionEngine jsExtractionEngine;
    private final BurpViewModel viewModel;
    private volatile IBurpExtenderCallbacks callbacks;
    private volatile IExtensionHelpers helpers;
    private final ScheduledThreadPoolExecutor executor;
    private final ConcurrentMap<String, Object> responseBaselines =
            new ConcurrentHashMap<String, Object>();
    private final Deque<TaskRecord> deferredTasks = new ConcurrentLinkedDeque<TaskRecord>();
    private final AtomicInteger scheduledTasks = new AtomicInteger(0);
    private final AtomicBoolean deferredPumpScheduled = new AtomicBoolean(false);
    private final AtomicBoolean closed = new AtomicBoolean(false);
    /** Explicit workbench pause. Legacy pause state is still observed through UiScanSnapshot. */
    private final AtomicBoolean workbenchPaused = new AtomicBoolean(false);
    /** User-visible compatibility result for Burp right-click registration. */
    private volatile String contextMenuStatus = "正在检测 Burp 右键菜单兼容性…";
    private final AtomicLong lastUiRefreshAt = new AtomicLong(0L);
    private final AtomicBoolean uiRefreshScheduled = new AtomicBoolean(false);
    /** Immutable configuration used by listener and worker threads. */
    private final AtomicReference<ScanConfig> settingsRef;
    /** Immutable EDT-built copy of legacy UI state consumed by listener and worker threads. */
    private final AtomicReference<UiScanSnapshot> uiSnapshotRef =
            new AtomicReference<UiScanSnapshot>(UiScanSnapshot.disabled());

    ScanOrchestratorCore(BurpExtender extender) {
        this.extender = extender;
        this.ruleLibraryRepository = new RuleLibraryRepository(extender);
        this.requestBuilder = new RequestBuilder(extender);
        this.jsExtractionEngine = new JsExtractionEngine(extender);
        this.viewModel = new BurpViewModel(extender);
        this.settingsRef = new AtomicReference<ScanConfig>(ScanConfigStore.load());
        this.executor = new ScheduledThreadPoolExecutor(WORKER_THREADS,
                new ReliabilityThreadFactory());
        this.executor.setRemoveOnCancelPolicy(true);
        this.executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        this.executor.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
    }

    void install(IBurpExtenderCallbacks callbackValue) {
        this.callbacks = callbackValue;
        try {
            this.helpers = callbackValue == null ? null : callbackValue.getHelpers();
        } catch (RuntimeException ignored) {
            this.helpers = null;
        }
        if (this.helpers == null) {
            try {
                Object value = readField(extender, "helpers");
                if (value instanceof IExtensionHelpers) {
                    this.helpers = (IExtensionHelpers) value;
                }
            } catch (Exception ignored) {
                // The original initializer controls helpers; a later enqueue will try again.
            }
        }
        viewModel.bindLegacyUiSnapshots(ruleLibraryRepository, snapshot -> uiSnapshotRef.set(snapshot));
        installReliabilityTab();
        installContextMenu();
    }

    void shutdown() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        viewModel.shutdown();
        executor.shutdownNow();
        deferredTasks.clear();
        resultRepository.clearSessionState();
        requestUiRefresh(true);
        log(extender, "[CGN] 可靠性调度器已停止。未完成任务状态已保留在本次 Burp 会话内。");
    }

    void enqueueAutomatic(int toolFlag, IHttpRequestResponse messageInfo) {
        ScanSource source = ScanSource.fromToolFlag(toolFlag);
        ScanConfig current = settingsRef.get();
        if (source == null || !current.enabled(source)) {
            return;
        }
        enqueue(messageInfo, source, false);
    }

    void enqueueManual(IHttpRequestResponse messageInfo) {
        enqueue(messageInfo, ScanSource.MANUAL, true);
    }

    boolean scopeRequired() {
        return settingsRef.get().scopeRequired;
    }

    ScanConfig config() {
        return settingsRef.get();
    }

    java.util.Map<String, TaskRecord> taskRecordsForDiagnostics() {
        return java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<String, TaskRecord>(
                resultRepository.records()));
    }

    UiScanSnapshot uiSnapshotForDiagnostics() { return uiSnapshotRef.get(); }

    ScanResultViewModel.ResultUiMetrics resultUiMetricsForDiagnostics() {
        return viewModel.resultUiMetrics();
    }

    java.util.List<BurpViewModel.TaskView> taskViewsForUi() {
        List<TaskRecord> records = new ArrayList<TaskRecord>(resultRepository.records().values());
        Collections.sort(records, new Comparator<TaskRecord>() {
            public int compare(TaskRecord left, TaskRecord right) {
                return Long.compare(right.updatedAt, left.updatedAt);
            }
        });
        List<BurpViewModel.TaskView> output = new ArrayList<BurpViewModel.TaskView>(records.size());
        for (TaskRecord record : records) {
            ScanPlan plan = record.plan;
            String url = plan == null || plan.baseUrl == null ? "" : plan.baseUrl.toExternalForm();
            String host = plan == null ? "" : safe(plan.normalizedHost);
            String source = plan == null || plan.source == null ? "" : plan.source.label;
            int attempts = record.attempts.get();
            output.add(new BurpViewModel.TaskView(record.key, source, host, url,
                    record.state == null ? "UNKNOWN" : record.state.name(), attempts,
                    record.message, record.createdAt, record.updatedAt));
        }
        return java.util.Collections.unmodifiableList(output);
    }

    String contextMenuStatus() { return contextMenuStatus; }

    boolean paused() { return isScanPaused(); }

    void setPaused(boolean paused) {
        workbenchPaused.set(paused);
        viewModel.setLegacyScanPaused(paused);
        if (!paused) scheduleDeferredPump();
        requestUiRefresh(true);
    }

    void requestResultViewRefresh(boolean filterChanged) {
        viewModel.requestResultViewRefresh(filterChanged);
    }

    private void enqueue(IHttpRequestResponse messageInfo, ScanSource source, boolean manual) {
        if (closed.get() || messageInfo == null) {
            return;
        }
        try {
            ScanPlan plan = createPlan(messageInfo, source, manual);
            if (plan == null) {
                return;
            }
            String key = buildTaskKey(plan);
            TaskRecord existing = resultRepository.records().get(key);
            if (existing != null) {
                TaskState state = existing.state;
                if (state == TaskState.PENDING || state == TaskState.RUNNING || state == TaskState.RETRYABLE
                        || state == TaskState.SUCCESS) {
                    return;
                }
            }
            TaskRecord candidate = new TaskRecord(key, plan);
            TaskRecord actual = resultRepository.records().putIfAbsent(key, candidate);
            if (actual != null) {
                if (actual.state == TaskState.FAILED || actual.state == TaskState.CANCELLED) {
                    actual.attempts.set(0);
                    actual.update(TaskState.PENDING, "Manually re-queued");
                    schedule(actual, 0L);
                }
                return;
            }
            evictTerminalRecordsIfNeeded();
            schedule(candidate, 0L);
            requestUiRefresh(false);
        } catch (Exception e) {
            log(extender, "[CGN] 创建扫描任务失败: " + safeMessage(e));
        }
    }

    private ScanPlan createPlan(IHttpRequestResponse original, ScanSource source, boolean manual)
            throws Exception {
        IExtensionHelpers activeHelpers = resolveHelpers();
        IBurpExtenderCallbacks activeCallbacks = resolveCallbacks();
        if (activeHelpers == null || activeCallbacks == null || original.getRequest() == null
                || original.getHttpService() == null) {
            return null;
        }
        UiScanSnapshot ui = uiSnapshotRef.get();
        if (!ui.pluginEnabled || !ui.directoryScanEnabled || isScanPaused()) {
            return null;
        }
        IRequestInfo info = activeHelpers.analyzeRequest(original);
        if (info == null || info.getUrl() == null) {
            return null;
        }
        URL url = info.getUrl();
        ScanConfig current = settingsRef.get();
        if (!isScopeAllowed(extender, activeCallbacks, url, current.scopeRequired)) {
            log(extender, "[CGN] 已拒绝超 Scope 任务: " + url);
            return null;
        }
        String host = normalizedHost(original);
        if (isBlank(host) || !passesHostFilters(host, ui)) {
            return null;
        }

        IHttpRequestResponse stored = original;
        try {
            IHttpRequestResponsePersisted persisted = activeCallbacks.saveBuffersToTempFiles(original);
            if (persisted != null) {
                stored = persisted;
                info = activeHelpers.analyzeRequest(stored);
                url = info == null ? url : info.getUrl();
            }
        } catch (RuntimeException ignored) {
            // Original object is still usable for a short queue residence. This is not fatal.
        }
        if (info == null || url == null) {
            return null;
        }
        RuleLibraryRepository.RuleSnapshot ruleSnapshot = ui.ruleSnapshot;
        List<String> dictionary = ruleSnapshot.pathEntries();
        List<LayeredDictionaryStore.DictionaryGroup> dictionaryGroups = ruleSnapshot.dictionaryGroups();
        List<Object> groups = ruleSnapshot.requestGroups();
        return new ScanPlan(stored, stored.getHttpService(), info, url, host, source, dictionary,
                dictionaryGroups, groups, ui.denyTokens, ui.intervalMillis,
                ruleSnapshot.version(), current, ui);
    }

    private String buildTaskKey(ScanPlan plan) {
        return plan.normalizedHost + "|" + canonicalBasePath(plan.baseUrl) + "|"
                + plan.templateVersion;
    }

    private void schedule(TaskRecord task, long delayMillis) {
        if (closed.get() || task == null) {
            return;
        }
        if (!task.scheduled.compareAndSet(false, true)) {
            return;
        }
        int limit = settingsRef.get().pendingLimit;
        int now = scheduledTasks.incrementAndGet();
        if (now > limit) {
            scheduledTasks.decrementAndGet();
            task.scheduled.set(false);
            defer(task, "Queue capacity reached; task retained for delayed dispatch");
            return;
        }
        task.update(delayMillis > 0L ? TaskState.RETRYABLE : TaskState.PENDING,
                delayMillis > 0L ? "Retry scheduled in " + delayMillis + " ms" : "Queued");
        try {
            executor.schedule(new Runnable() {
                public void run() {
                    try {
                        task.scheduled.set(false);
                        executeTask(task);
                    } finally {
                        scheduledTasks.decrementAndGet();
                        scheduleDeferredPump();
                    }
                }
            }, Math.max(0L, delayMillis), TimeUnit.MILLISECONDS);
        } catch (RuntimeException e) {
            scheduledTasks.decrementAndGet();
            task.scheduled.set(false);
            defer(task, "Executor rejected task; retained for delayed retry");
        }
    }

    private void defer(TaskRecord task, String reason) {
        if (task.deferred.compareAndSet(false, true)) {
            if (deferredTasks.size() >= HARD_MAX_DEFERRED) {
                task.deferred.set(false);
                task.update(TaskState.FAILED, "Deferred queue hard limit reached; retry manually after load decreases");
                log(extender, "[CGN] 延迟队列达到上限，任务未静默丢弃，已标记为失败: " + task.key);
                requestUiRefresh(false);
                return;
            }
            task.update(TaskState.RETRYABLE, reason);
            deferredTasks.addLast(task);
        }
        scheduleDeferredPump();
        requestUiRefresh(false);
    }

    private void scheduleDeferredPump() {
        if (closed.get() || deferredTasks.isEmpty() || !deferredPumpScheduled.compareAndSet(false, true)) {
            return;
        }
        try {
            executor.schedule(new Runnable() {
                public void run() {
                    try {
                        drainDeferredTasks();
                    } finally {
                        deferredPumpScheduled.set(false);
                        if (!deferredTasks.isEmpty() && !closed.get()) {
                            scheduleDeferredPump();
                        }
                    }
                }
            }, 250L, TimeUnit.MILLISECONDS);
        } catch (RuntimeException e) {
            deferredPumpScheduled.set(false);
        }
    }

    private void drainDeferredTasks() {
        int slots = Math.max(0, settingsRef.get().pendingLimit - scheduledTasks.get());
        while (slots-- > 0) {
            TaskRecord task = deferredTasks.pollFirst();
            if (task == null) {
                return;
            }
            task.deferred.set(false);
            if (task.state == TaskState.SUCCESS || task.state == TaskState.CANCELLED) {
                continue;
            }
            schedule(task, 0L);
        }
    }

    private void executeTask(TaskRecord task) {
        if (closed.get()) {
            task.update(TaskState.CANCELLED, "Extension unloaded");
            return;
        }
        if (isScanPaused()) {
            task.update(TaskState.RETRYABLE, "Plugin scan is paused");
            defer(task, "Plugin scan is paused");
            return;
        }
        int attempt = task.attempts.incrementAndGet();
        task.update(TaskState.RUNNING, "Running attempt " + attempt);
        requestUiRefresh(false);

        ExecutionResult result;
        try {
            result = executePlan(task.plan);
        } catch (Exception e) {
            result = ExecutionResult.retryable("Unhandled worker exception: " + safeMessage(e));
        }
        if (result.cancelled) {
            task.update(TaskState.CANCELLED, result.detail);
        } else if (result.budgetBlocked) {
            task.update(TaskState.FAILED, result.detail);
        } else if (result.retryable && attempt <= task.plan.settings.maxRetries) {
            long delay = retryDelay(task.plan.settings, attempt);
            task.update(TaskState.RETRYABLE, result.detail + "; retry " + attempt + "/"
                    + task.plan.settings.maxRetries);
            schedule(task, delay);
        } else if (result.retryable) {
            task.update(TaskState.FAILED, result.detail + "; retry budget exhausted");
        } else {
            task.update(TaskState.SUCCESS, result.detail);
        }
        requestUiRefresh(false);
    }

    private ExecutionResult executePlan(ScanPlan plan) throws Exception {
        if (plan == null || plan.seed == null || plan.service == null || plan.baseRequestInfo == null) {
            return ExecutionResult.cancelled("Incomplete task plan");
        }
        if (isScanPaused()) {
            return ExecutionResult.cancelled("Plugin scan is paused");
        }
        addHostIfAbsent(plan.normalizedHost);

        // Preserve original JS extraction behavior once per accepted seed response.
        try {
            jsExtractionEngine.extract(plan.seed, plan.source.toolFlag);
        } catch (Exception e) {
            log(extender, "[CGN] JS 提取失败但目录扫描继续: " + safeMessage(e));
        }

        if (plan.dictionaryGroups.isEmpty() || plan.requestGroups.isEmpty()) {
            return ExecutionResult.success("No enabled dictionary group or request template entries");
        }

        List<String> ancestorDirectories = buildAncestorDirectories(plan.baseUrl);
        boolean observedNetworkFailure = false;
        boolean budgetBlocked = false;
        Set<String> baselineAttemptedInRun = new HashSet<String>();
        int evaluated = 0;
        int responses = 0;
        String lastFailure = "";

        for (int level = 0; level < ancestorDirectories.size(); level++) {
            if (isScanPaused()) {
                return ExecutionResult.cancelled("Plugin scan is paused");
            }
            String observedParent = ancestorDirectories.get(level);
            rememberTestedPath(originFor(plan.baseUrl) + observedParent);

            for (LayeredDictionaryStore.DictionaryGroup dictionaryGroup : plan.dictionaryGroups) {
                if (!dictionaryGroup.matchesLevel(level)) {
                    continue;
                }
                List<Object> eligibleTemplates = ScanPathPlanner.eligibleTemplatesFor(plan, dictionaryGroup, level, requestBuilder);
                if (eligibleTemplates.isEmpty()) {
                    continue;
                }
                String scanParent = ScanPathPlanner.resolveDictionaryBaseDirectory(ancestorDirectories, level, dictionaryGroup.strategy);
                rememberTestedPath(originFor(plan.baseUrl) + scanParent);
                int groupRequests = 0;

                for (String rawEntry : dictionaryGroup.entries) {
                    if (isScanPaused()) {
                        return ExecutionResult.cancelled("Plugin scan is paused");
                    }
                    if (groupRequests >= dictionaryGroup.maxRequests) {
                        log(extender, "[CGN] 字典组达到本轮请求上限，已停止该组: " + dictionaryGroup.summary());
                        break;
                    }
                    String entry = safe(rawEntry).trim();
                    if (entry.length() == 0) {
                        continue;
                    }
                    String candidatePath = ScanPathPlanner.buildDictionaryCandidate(scanParent, entry, dictionaryGroup.strategy);
                    if (containsDeniedToken(candidatePath, plan.denyTokens)) {
                        continue;
                    }
                    for (Object group : eligibleTemplates) {
                        BaselineFetch baseline = getReliableBaseline(plan, scanParent, group, baselineAttemptedInRun);
                        if (baseline.budgetBlocked) {
                            budgetBlocked = true;
                            break;
                        }
                        if (baseline.retryable) {
                            observedNetworkFailure = true;
                            lastFailure = "Soft-404 baseline request returned no response";
                        }
                        String target = buildRequestTarget(candidatePath, scanParent, group);
                        String probeKey = ScanPathPlanner.buildProbeKey(plan, target, group, dictionaryGroup);
                        if (!claimProbe(probeKey)) {
                            continue;
                        }
                        evaluated++;
                        groupRequests++;
                        if (isLegacyBudgetExceeded(plan.normalizedHost)) {
                            releaseProbe(probeKey);
                            budgetBlocked = true;
                            break;
                        }

                        byte[] request;
                        try {
                            request = buildRequest(plan, target, group);
                        } catch (Exception e) {
                            releaseProbe(probeKey);
                            observedNetworkFailure = true;
                            lastFailure = "Request construction failed: " + safeMessage(e);
                            continue;
                        }
                        if (request == null || request.length == 0) {
                            releaseProbe(probeKey);
                            observedNetworkFailure = true;
                            lastFailure = "Request construction returned empty bytes";
                            continue;
                        }

                        IHttpRequestResponse response;
                        try {
                            response = resolveCallbacks().makeHttpRequest(plan.service, request);
                        } catch (RuntimeException e) {
                            releaseProbe(probeKey);
                            observedNetworkFailure = true;
                            lastFailure = "HTTP request error: " + safeMessage(e);
                            continue;
                        }
                        if (response == null || response.getResponse() == null) {
                            releaseProbe(probeKey);
                            observedNetworkFailure = true;
                            lastFailure = "HTTP request returned no response";
                            continue;
                        }

                        // Commit only after there is a usable response. This preserves the original
                        // global/host counters and status widgets without consuming budget on failures.
                        completeProbe(probeKey);
                        commitLegacyBudgetAndDedup(probeKey, plan.normalizedHost);
                        responses++;
                        try {
                            addFindingLog(plan, response, target, group, baseline.signature);
                        } catch (Exception e) {
                            log(extender, "[CGN] 响应已成功获取，但结果记录失败: " + safeMessage(e));
                        }
                    }
                    if (budgetBlocked) {
                        break;
                    }
                    sleepRespectingInterrupt(plan.intervalMillis);
                }
                if (budgetBlocked) {
                    break;
                }
            }
            if (budgetBlocked) {
                break;
            }
        }
        requestUiRefresh(false);
        if (budgetBlocked) {
            return ExecutionResult.budget("Global or per-host request budget reached after " + responses
                    + " valid responses; retry after resetting the scan budget");
        }
        if (observedNetworkFailure) {
            return ExecutionResult.retryable((lastFailure.length() == 0 ? "Network failure" : lastFailure)
                    + "; valid responses=" + responses + ", evaluated=" + evaluated);
        }
        return ExecutionResult.success("Completed: valid responses=" + responses + ", evaluated=" + evaluated);
    }

    private BaselineFetch getReliableBaseline(ScanPlan plan, String parent, Object group,
                                              Set<String> attemptedInRun) {
        String method = fieldStringQuietly(group, "method").trim().toUpperCase(Locale.ROOT);
        if (!("GET".equals(method) || "HEAD".equals(method))) {
            return BaselineFetch.none();
        }
        String cacheKey = plan.normalizedHost + "|" + parent + "|"
                + fieldStringQuietly(group, "name") + "|" + plan.templateVersion;
        Object cached = responseBaselines.get(cacheKey);
        if (cached != null) {
            return new BaselineFetch(cached, false, false);
        }
        if (!attemptedInRun.add(cacheKey)) {
            return BaselineFetch.none();
        }
        String token = ".cgn-baseline-" + sha256(cacheKey).substring(0, 10);
        String candidate = joinPath(parent, token);
        String target;
        try {
            target = buildRequestTarget(candidate, parent, group);
        } catch (Exception e) {
            return BaselineFetch.none();
        }
        String probeKey = "baseline|" + ScanPathPlanner.buildProbeKey(plan, target, group);
        if (!claimProbe(probeKey)) {
            return BaselineFetch.none();
        }
        if (isLegacyBudgetExceeded(plan.normalizedHost)) {
            releaseProbe(probeKey);
            return BaselineFetch.budget();
        }
        try {
            byte[] request = buildRequest(plan, target, group);
            if (request == null || request.length == 0) {
                releaseProbe(probeKey);
                return BaselineFetch.retryable();
            }
            IHttpRequestResponse response = resolveCallbacks().makeHttpRequest(plan.service, request);
            if (response == null || response.getResponse() == null) {
                releaseProbe(probeKey);
                return BaselineFetch.retryable();
            }
            IExtensionHelpers activeHelpers = resolveHelpers();
            IResponseInfo info = activeHelpers == null ? null : activeHelpers.analyzeResponse(response.getResponse());
            int status = info == null ? 0 : info.getStatusCode();
            Object signature = invokePrivate(extender, "buildResponseSignature",
                    new Class<?>[] { IHttpRequestResponse.class, int.class },
                    new Object[] { response, Integer.valueOf(status) });
            completeProbe(probeKey);
            commitLegacyBudgetAndDedup(probeKey, plan.normalizedHost);
            if (signature != null) {
                if (responseBaselines.size() >= 1000) {
                    responseBaselines.clear();
                }
                responseBaselines.put(cacheKey, signature);
            }
            return new BaselineFetch(signature, false, false);
        } catch (Exception e) {
            releaseProbe(probeKey);
            return BaselineFetch.retryable();
        }
    }

    private boolean claimProbe(String key) { return probeRegistry.claim(key); }

    private void completeProbe(String key) { probeRegistry.complete(key); }

    private void releaseProbe(String key) { probeRegistry.release(key); }

    void retryFailed() {
        int queued = 0;
        for (TaskRecord task : resultRepository.records().values()) {
            if (retryTaskInternal(task, "Manual retry requested")) queued++;
        }
        log(extender, "[CGN] 已重新排队失败/取消任务: " + queued);
        requestUiRefresh(true);
    }

    void retryTask(String key) {
        if (isBlank(key)) return;
        TaskRecord task = resultRepository.records().get(key);
        if (task == null) return;
        if (retryTaskInternal(task, "Manual retry requested from workbench")) {
            log(extender, "[CGN] 已重新排队任务: " + task.plan.normalizedHost);
            requestUiRefresh(true);
        }
    }

    private boolean retryTaskInternal(TaskRecord task, String reason) {
        if (task == null) return false;
        if (task.state != TaskState.FAILED && task.state != TaskState.CANCELLED
                && task.state != TaskState.RETRYABLE) return false;
        task.attempts.set(0);
        task.update(TaskState.PENDING, reason);
        schedule(task, 0L);
        return true;
    }

    private void evictTerminalRecordsIfNeeded() {
        if (resultRepository.records().size() <= HARD_MAX_TASK_RECORDS) {
            return;
        }
        List<TaskRecord> terminal = new ArrayList<TaskRecord>();
        for (TaskRecord record : resultRepository.records().values()) {
            if (record.state == TaskState.SUCCESS || record.state == TaskState.FAILED
                    || record.state == TaskState.CANCELLED) {
                terminal.add(record);
            }
        }
        Collections.sort(terminal, new Comparator<TaskRecord>() {
            public int compare(TaskRecord left, TaskRecord right) {
                return Long.compare(left.updatedAt, right.updatedAt);
            }
        });
        int remove = Math.max(0, resultRepository.records().size() - HARD_MAX_TASK_RECORDS);
        for (int i = 0; i < terminal.size() && i < remove; i++) {
            resultRepository.records().remove(terminal.get(i).key, terminal.get(i));
        }
    }

    private boolean isScanPaused() {
        return workbenchPaused.get() || uiSnapshotRef.get().scanPaused;
    }

    String normalizedHost(IHttpRequestResponse message) {
        try {
            Object result = invokePrivate(extender, "getNormalizedRequestHost",
                    new Class<?>[] { IHttpRequestResponse.class }, new Object[] { message });
            return safe(result == null ? "" : String.valueOf(result));
        } catch (Exception e) {
            try {
                IExtensionHelpers activeHelpers = resolveHelpers();
                IRequestInfo info = activeHelpers == null ? null : activeHelpers.analyzeRequest(message);
                URL url = info == null ? null : info.getUrl();
                return url == null ? "" : url.getHost().toLowerCase(Locale.ROOT);
            } catch (Exception ignored) {
                return "";
            }
        }
    }

    private boolean passesHostFilters(String host, UiScanSnapshot snapshot) {
        if (snapshot.whiteListEnabled && !hostMatchesList(host, snapshot.whiteListRules)) return false;
        return !snapshot.blackListEnabled || !hostMatchesList(host, snapshot.blackListRules);
    }

    private boolean hostMatchesList(String host, String rules) {
        try {
            Object result = invokePrivate(extender, "hostMatchesList",
                    new Class<?>[] { String.class, String.class }, new Object[] { host, rules });
            return Boolean.TRUE.equals(result);
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean isGroupEnabledAtLevel(Object group, int level, UiScanSnapshot snapshot) {
        return requestBuilder.isGroupEnabledAtLevel(group, level, snapshot);
    }

    private String buildRequestTarget(String candidate, String parent, Object group) throws Exception {
        return requestBuilder.buildTarget(candidate, parent, group);
    }

    private byte[] buildRequest(ScanPlan plan, String target, Object group) {
        return requestBuilder.buildRequest(resolveHelpers(), plan.baseRequestInfo, target, group,
                plan.uiSnapshot.extraHeaders, plan.settings);
    }

    private boolean containsDeniedToken(String path, String tokens) {
        return requestBuilder.containsDeniedToken(path, tokens);
    }

    private boolean isLegacyBudgetExceeded(String host) {
        try {
            Object result = invokePrivate(extender, "isScanBudgetExceeded",
                    new Class<?>[] { String.class }, new Object[] { host });
            return Boolean.TRUE.equals(result);
        } catch (Exception e) {
            return false;
        }
    }

    private void commitLegacyBudgetAndDedup(String probeKey, String host) {
        try {
            invokePrivate(extender, "markScanRequest", new Class<?>[] { String.class, String.class },
                    new Object[] { probeKey, host });
        } catch (Exception e) {
            log(extender, "[CGN] 已获得响应，但提交旧版统计失败: " + safeMessage(e));
        }
    }

    private void addFindingLog(ScanPlan plan, IHttpRequestResponse response,
                               String target, Object group, Object baseline) throws Exception {
        IExtensionHelpers activeHelpers = resolveHelpers();
        IBurpExtenderCallbacks activeCallbacks = resolveCallbacks();
        if (activeHelpers == null || activeCallbacks == null) {
            return;
        }
        IResponseInfo responseInfo = activeHelpers.analyzeResponse(response.getResponse());
        int status = responseInfo == null ? 0 : responseInfo.getStatusCode();
        Class<?> groupType = Class.forName("burp.BurpExtender$RequestGroup");
        Class<?> signatureType = Class.forName("burp.BurpExtender$ResponseSignature");
        Object finding = invokePrivate(extender, "classifyFinding",
                new Class<?>[] { String.class, IHttpRequestResponse.class, int.class, groupType, signatureType },
                new Object[] { originFor(plan.baseUrl) + target, response, Integer.valueOf(status), group, baseline });
        if (finding == null) {
            return;
        }
        String tag = fieldString(finding, "tag");
        String risk = fieldString(finding, "risk");
        String reason = fieldString(finding, "reason");
        String displayTag = String.valueOf(invokePrivate(extender, "buildRequestGroupDisplayTag",
                new Class<?>[] { groupType }, new Object[] { group }));
        String method = activeHelpers.analyzeRequest(response.getRequest()).getMethod();
        IHttpRequestResponsePersisted persisted = activeCallbacks.saveBuffersToTempFiles(response);
        int bodyLength = intValue(invokePrivate(extender, "getResponseBodyLength",
                new Class<?>[] { IHttpRequestResponse.class }, new Object[] { response }));
        Class<?> logEntryType = Class.forName("burp.BurpExtender$LogEntry");
        Constructor<?> constructor = logEntryType.getDeclaredConstructor(String.class,
                IHttpRequestResponsePersisted.class, String.class, String.class, String.class,
                String.class, int.class, int.class);
        constructor.setAccessible(true);
        Object logEntry = constructor.newInstance(method, persisted,
                originFor(plan.baseUrl) + target, displayTag, risk,
                safe(tag) + (isBlank(reason) ? "" : ": " + reason), bodyLength, status);
        invokePrivate(extender, "addScanLogEntry", new Class<?>[] { logEntryType }, new Object[] { logEntry });
        viewModel.onScanLogEntryAdded(logEntry);
    }

    private void rememberTestedPath(String value) {
        try {
            invokePrivate(extender, "rememberTestedPath", new Class<?>[] { String.class }, new Object[] { value });
        } catch (Exception ignored) {
            // Path history is UX only; it must not break a network task.
        }
    }

    @SuppressWarnings("unchecked")
    private void addHostIfAbsent(String host) {
        if (isBlank(host)) {
            return;
        }
        try {
            Object listValue = readField(extender, "log_host");
            if (!(listValue instanceof List<?>)) {
                return;
            }
            List<Object> hosts = (List<Object>) listValue;
            synchronized (hosts) {
                for (Object existing : hosts) {
                    if (host.equals(fieldString(existing, "HOST_data"))) {
                        return;
                    }
                }
                if (hosts.size() >= 300) {
                    hosts.remove(0);
                }
                Class<?> hostType = Class.forName("burp.BurpExtender$Request_HOST");
                Constructor<?> constructor = hostType.getDeclaredConstructor(String.class);
                constructor.setAccessible(true);
                hosts.add(constructor.newInstance(host));
            }
        } catch (Exception ignored) {
            // Optional host table enrichment only.
        }
    }



    private IExtensionHelpers resolveHelpers() {
        if (helpers != null) {
            return helpers;
        }
        try {
            Object value = readField(extender, "helpers");
            if (value instanceof IExtensionHelpers) {
                helpers = (IExtensionHelpers) value;
                return helpers;
            }
        } catch (Exception ignored) {
            // deferred initialization.
        }
        return null;
    }

    private IBurpExtenderCallbacks resolveCallbacks() {
        if (callbacks != null) {
            return callbacks;
        }
        try {
            Object value = readField(extender, "callbacks");
            if (value instanceof IBurpExtenderCallbacks) {
                callbacks = (IBurpExtenderCallbacks) value;
                return callbacks;
            }
        } catch (Exception ignored) {
            // deferred initialization.
        }
        return null;
    }

    private void installReliabilityTab() {
        viewModel.installReliabilityTab(new BurpViewModel.ReliabilityController() {
            public ScanConfig config() { return settingsRef.get(); }
            public void updateConfig(ScanConfig next) { updateScanConfig(next); }
            public void retryFailed() { ScanOrchestratorCore.this.retryFailed(); }
            public void retryTask(String key) { ScanOrchestratorCore.this.retryTask(key); }
            public void setPaused(boolean paused) { ScanOrchestratorCore.this.setPaused(paused); }
            public boolean paused() { return ScanOrchestratorCore.this.isScanPaused(); }
            public java.util.List<BurpViewModel.TaskView> taskViews() { return ScanOrchestratorCore.this.taskViewsForUi(); }
            public String contextMenuStatus() { return ScanOrchestratorCore.this.contextMenuStatus(); }
            public BurpViewModel.ScanStatus status() { return currentStatus(); }
            public void log(String line) { CgnReliability.log(extender, line); }
        });
    }





    private void updateScanConfig(ScanConfig next) {
        if (next == null) return;
        settingsRef.set(next);
        ScanConfigStore.save(next);
        scheduleDeferredPump();
        updateStatusLabel();
    }

    private void updateStatusLabel() {
        viewModel.renderStatus(currentStatus());
    }

    private BurpViewModel.ScanStatus currentStatus() {
        int pending = 0;
        int running = 0;
        int success = 0;
        int retryable = 0;
        int failed = 0;
        int cancelled = 0;
        for (TaskRecord record : resultRepository.records().values()) {
            switch (record.state) {
                case PENDING: pending++; break;
                case RUNNING: running++; break;
                case SUCCESS: success++; break;
                case RETRYABLE: retryable++; break;
                case FAILED: failed++; break;
                case CANCELLED: cancelled++; break;
                default: break;
            }
        }
        return new BurpViewModel.ScanStatus(isScanPaused(), pending, running, retryable, success, failed, cancelled,
                deferredTasks.size(), resultRepository.inFlightProbeKeys().size(),
                resultRepository.completedProbeKeys().size());
    }

    private void installContextMenu() {
        IBurpExtenderCallbacks activeCallbacks = resolveCallbacks();
        if (activeCallbacks == null) {
            return;
        }
        try {
            ClassLoader loader = activeCallbacks.getClass().getClassLoader();
            Class<?> factoryType;
            try {
                factoryType = Class.forName("burp.IContextMenuFactory", false, loader);
            } catch (ClassNotFoundException first) {
                factoryType = Class.forName("burp.IContextMenuFactory");
            }
            Object proxy = Proxy.newProxyInstance(factoryType.getClassLoader(),
                    new Class<?>[] { factoryType }, new burp.ui.ContextMenuHandler(new ScanOrchestrator(this)));
            Method register = activeCallbacks.getClass().getMethod("registerContextMenuFactory", factoryType);
            register.invoke(activeCallbacks, proxy);
            contextMenuStatus = "已注册：选中请求 / 当前 Host / 重试失败任务";
            log(extender, "[CGN] Burp 右键菜单已注册：扫描选中请求 / 当前 Host / 重试失败任务。");
        } catch (Exception e) {
            contextMenuStatus = "当前 Burp API 不支持，已跳过；请使用支持该 API 的 Burp 版本";
            log(extender, "[CGN] 当前 Burp API 未提供 IContextMenuFactory，已跳过右键菜单: " + safeMessage(e));
        }
    }

    private void requestUiRefresh(boolean immediate) {
        long now = System.currentTimeMillis();
        long last = lastUiRefreshAt.get();
        if (!immediate && now - last < UI_REFRESH_MIN_INTERVAL_MS) {
            if (!uiRefreshScheduled.compareAndSet(false, true)) {
                return;
            }
            long delay = UI_REFRESH_MIN_INTERVAL_MS - (now - last);
            try {
                executor.schedule(new Runnable() {
                    public void run() {
                        uiRefreshScheduled.set(false);
                        requestUiRefresh(true);
                    }
                }, delay, TimeUnit.MILLISECONDS);
            } catch (RuntimeException ignored) {
                uiRefreshScheduled.set(false);
            }
            return;
        }
        lastUiRefreshAt.set(now);
        viewModel.requestResultViewRefresh(immediate);
        updateStatusLabel();
    }
}
