package burp;

import burp.*;
import burp.bootstrap.*;
import burp.config.*;
import burp.dictionary.*;
import burp.fingerprint.*;
import burp.js.*;
import burp.request.*;
import burp.result.*;
import burp.traffic.*;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Compatibility enhancement layer for CGN Pen-testing V5.6.1.
 *
 * It intentionally changes only four behavioral seams:
 * 1) accepted passive traffic sources; 2) scanner issue reporting for low/info;
 * 3) safe active verification through an insertion point; 4) fingerprint expression matching.
 */
final class CgnEnhancement {
    private static final Set<Integer> AUTO_SCAN_TOOL_FLAGS = Collections.unmodifiableSet(
            new HashSet<Integer>(Arrays.asList(2, 4, 16, 32, 64)));
    // Target, Proxy, Scanner, Intruder, Repeater. Extender-originated traffic is deliberately excluded.

    private static final int MAX_PROBE_RESPONSE_CHARS = 128 * 1024;
    private static final int MAX_ACTIVE_DEDUP_KEYS = 50_000;
    private static final ConcurrentMap<String, Boolean> ACTIVE_PROBE_KEYS =
            new ConcurrentHashMap<String, Boolean>();

    private static final ConcurrentMap<String, Method> METHOD_CACHE =
            new ConcurrentHashMap<String, Method>();
    private static final ConcurrentMap<String, Field> FIELD_CACHE =
            new ConcurrentHashMap<String, Field>();

    private static final Set<String> SAFE_ACTIVE_METHODS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList("GET", "HEAD", "OPTIONS")));
    private static final String[] ERROR_MARKERS = new String[] {
            "sql syntax", "syntax error", "stack trace", "stacktrace", "traceback",
            "nullpointerexception", "illegalargumentexception", "fatal error",
            "unhandled exception", "internal server error"
    };

    private CgnEnhancement() {
    }

    static void registerExtenderCallbacks(BurpExtender extender, IBurpExtenderCallbacks callbacks) {
        ExtensionBootstrap.register(extender, callbacks);
    }

    static void extensionUnloaded(BurpExtender extender) {
        ExtensionBootstrap.unload(extender);
    }

    static void processHttpMessage(BurpExtender extender, int toolFlag,
                                   boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        ExtensionBootstrap.onHttpMessage(extender, toolFlag, messageIsRequest, messageInfo);
    }

    /** Patched replacement for the legacy full-log filter rebuild. */
    static void scanUriFilter(BurpExtender extender) {
        if (CgnReliability.requestResultViewRefresh(extender, true)) return;
        try {
            BurpExtensionAccess.invokePrivate(extender, "cgn$scanUriFilterLegacy",
                    new Class<?>[0], new Object[0]);
        } catch (Exception error) {
            log(extender, "[CGN] 结果筛选初始化失败: " + safeMessage(error));
        }
    }

    /** Patched replacement for a whole-table data event while the indexed result view is active. */
    static void fireScanTableChanged(BurpExtender extender) {
        if (CgnReliability.requestResultViewRefresh(extender, false)) return;
        try {
            BurpExtensionAccess.invokePrivate(extender, "cgn$fireScanTableChangedLegacy",
                    new Class<?>[0], new Object[0]);
        } catch (Exception error) {
            log(extender, "[CGN] 结果表初始化刷新失败: " + safeMessage(error));
        }
    }

    @SuppressWarnings("unchecked")
    static List<IScanIssue> doPassiveScan(BurpExtender extender, IHttpRequestResponse messageInfo) {
        if (messageInfo == null) {
            return null;
        }
        try {
            Object result = invokeLegacy(extender, "cgn$doPassiveScanHighMedium",
                    new Class<?>[] { IHttpRequestResponse.class }, new Object[] { messageInfo });
            List<IScanIssue> legacyIssues = result == null
                    ? Collections.<IScanIssue>emptyList()
                    : (List<IScanIssue>) result;
            if (!legacyIssues.isEmpty()) {
                return deduplicate(legacyIssues);
            }

            IScanIssue lowOrInfo = createLowOrInformationFindingIssue(extender, messageInfo);
            return lowOrInfo == null ? null : Collections.singletonList(lowOrInfo);
        } catch (Exception e) {
            log(extender, "[CGN] 被动指纹分析失败: " + safeMessage(e));
            return null;
        }
    }

    static List<IScanIssue> doActiveScan(BurpExtender extender,
                                         IHttpRequestResponse baseRequestResponse,
                                         IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        appendAll(issues, doPassiveScan(extender, baseRequestResponse));

        if (baseRequestResponse == null || insertionPoint == null) {
            return issues.isEmpty() ? null : deduplicate(issues);
        }

        String probeKey = null;
        boolean probeClaimed = false;
        try {
            IExtensionHelpers helpers = getHelpers(extender);
            IBurpExtenderCallbacks callbacks = getCallbacks(extender);
            if (helpers == null || callbacks == null || baseRequestResponse.getRequest() == null
                    || baseRequestResponse.getHttpService() == null) {
                return issues.isEmpty() ? null : deduplicate(issues);
            }

            IRequestInfo baseRequestInfo = helpers.analyzeRequest(baseRequestResponse);
            if (baseRequestInfo == null || !SAFE_ACTIVE_METHODS.contains(
                    safeUpper(baseRequestInfo.getMethod()))) {
                log(extender, "[CGN] 主动验证已跳过：仅对 GET / HEAD / OPTIONS 发起无副作用探针。");
                return issues.isEmpty() ? null : deduplicate(issues);
            }
            if (!CgnReliability.isActiveScopeAllowed(extender, callbacks, baseRequestInfo.getUrl())) {
                log(extender, "[CGN] 主动验证已拒绝：目标不在 Burp Scope 内。");
                return issues.isEmpty() ? null : deduplicate(issues);
            }

            probeKey = buildProbeKey(baseRequestInfo, insertionPoint);
            probeClaimed = CgnReliability.claimActiveProbe(probeKey);
            if (!probeClaimed) {
                return issues.isEmpty() ? null : deduplicate(issues);
            }

            String marker = "cgnprobe" + Long.toUnsignedString(System.nanoTime(), 36);
            byte[] payload = marker.getBytes(StandardCharsets.US_ASCII);
            byte[] probeRequest = buildInsertionPointRequest(insertionPoint, payload);
            if (probeRequest == null || probeRequest.length == 0) {
                log(extender, "[CGN] 主动验证已跳过：当前插入点不支持 buildRequest(byte[])。");
                return issues.isEmpty() ? null : deduplicate(issues);
            }

            IHttpRequestResponse probeResult = CgnReliability.executeSafeActiveProbe(extender, callbacks,
                    baseRequestResponse.getHttpService(), probeRequest, probeKey);
            if (probeResult == null || probeResult.getResponse() == null) {
                return issues.isEmpty() ? null : deduplicate(issues);
            }
            CgnReliability.completeActiveProbe(probeKey);
            probeClaimed = false;

            // Reuse the same fingerprint engine for the mutated response as for passive traffic.
            appendAll(issues, doPassiveScan(extender, probeResult));
            IScanIssue activeEvidence = createActiveVerificationIssue(
                    helpers, baseRequestResponse, probeResult, marker);
            if (activeEvidence != null) {
                issues.add(activeEvidence);
            }
        } catch (Exception e) {
            log(extender, "[CGN] 主动验证失败: " + safeMessage(e));
        } finally {
            // A build/network/runtime failure must not poison the active-scan dedup cache.
            if (probeClaimed && probeKey != null) {
                CgnReliability.releaseActiveProbe(probeKey);
            }
        }

        return issues.isEmpty() ? null : deduplicate(issues);
    }

    /**
     * Backwards-compatible fingerprint expression syntax:
     * - newline and a single '|' are AND separators (same semantics as V5.6.1)
     * - 'a || b' is an OR group
     * - !token is a negative condition
     * - url:, header:, body: scopes a literal to that evidence source
     * - re: compiles a case-insensitive regular expression
     */
    static boolean matchesFingerprintKeywords(String content, String expression) {
        return FingerprintEngine.matches(content, expression);
    }

    private static IScanIssue createLowOrInformationFindingIssue(BurpExtender extender,
                                                                   IHttpRequestResponse messageInfo)
            throws Exception {
        IExtensionHelpers helpers = getHelpers(extender);
        if (helpers == null || messageInfo.getResponse() == null) {
            return null;
        }
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
        if (requestInfo == null || responseInfo == null || requestInfo.getUrl() == null) {
            return null;
        }

        Object finding = invokeClassifier(extender, String.valueOf(requestInfo.getUrl()),
                messageInfo, (int) responseInfo.getStatusCode());
        if (finding == null) {
            return null;
        }

        String risk = readStringField(finding, "risk");
        if (!isLowOrInformation(risk)) {
            return null;
        }
        String tag = readStringField(finding, "tag");
        String reason = readStringField(finding, "reason");
        return new EnhancedScanIssue(messageInfo.getHttpService(), requestInfo.getUrl(),
                new IHttpRequestResponse[] { messageInfo },
                "[CGN] " + emptyFallback(tag, "Fingerprint"), toBurpSeverity(risk), "Certain",
                emptyFallback(reason, "Low/Information fingerprint finding exposed by CGN."));
    }

    private static Object invokeClassifier(BurpExtender extender, String url,
                                           IHttpRequestResponse messageInfo, int statusCode)
            throws Exception {
        Class<?> requestGroup = Class.forName("burp.BurpExtender$RequestGroup");
        Class<?> responseSignature = Class.forName("burp.BurpExtender$ResponseSignature");
        Method method = privateMethod(extender.getClass(), "classifyFinding",
                String.class, IHttpRequestResponse.class, int.class,
                requestGroup, responseSignature);
        return method.invoke(extender, url, messageInfo, Integer.valueOf(statusCode), null, null);
    }

    private static IScanIssue createActiveVerificationIssue(IExtensionHelpers helpers,
                                                              IHttpRequestResponse original,
                                                              IHttpRequestResponse probe,
                                                              String marker) {
        if (helpers == null || probe == null || probe.getResponse() == null) {
            return null;
        }
        try {
            String originalText = responseText(helpers, original);
            String probeText = responseText(helpers, probe);
            String lowerProbe = probeText.toLowerCase(Locale.ROOT);
            String lowerOriginal = originalText.toLowerCase(Locale.ROOT);
            boolean reflected = lowerProbe.contains(marker.toLowerCase(Locale.ROOT));
            boolean newError = hasErrorMarker(lowerProbe) && !hasErrorMarker(lowerOriginal);
            if (!reflected && !newError) {
                return null;
            }

            IRequestInfo probeInfo = helpers.analyzeRequest(probe);
            URL url = probeInfo == null ? null : probeInfo.getUrl();
            if (url == null || probe.getHttpService() == null) {
                return null;
            }

            if (newError) {
                return new EnhancedScanIssue(probe.getHttpService(), url,
                        new IHttpRequestResponse[] { original, probe },
                        "[CGN] Active verification: abnormal error behavior",
                        "Low", "Tentative",
                        "A non-destructive alphanumeric probe produced a new server-side error marker. "
                                + "Review the paired request/response before treating it as a vulnerability.");
            }
            return new EnhancedScanIssue(probe.getHttpService(), url,
                    new IHttpRequestResponse[] { original, probe },
                    "[CGN] Active verification: controllable input reflection",
                    "Information", "Tentative",
                    "A non-destructive alphanumeric marker was reflected in the response. "
                            + "This is an evidence finding only; validate context and output encoding manually.");
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static String responseText(IExtensionHelpers helpers, IHttpRequestResponse item) {
        if (item == null || item.getResponse() == null) {
            return "";
        }
        String text = helpers.bytesToString(item.getResponse());
        return text == null ? "" : text.substring(0, Math.min(text.length(), MAX_PROBE_RESPONSE_CHARS));
    }

    private static boolean hasErrorMarker(String text) {
        for (String marker : ERROR_MARKERS) {
            if (text.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    private static byte[] buildInsertionPointRequest(IScannerInsertionPoint insertionPoint,
                                                      byte[] payload) {
        try {
            Method candidate = null;
            for (Method method : insertionPoint.getClass().getMethods()) {
                if ("buildRequest".equals(method.getName())
                        && method.getParameterTypes().length == 1
                        && method.getParameterTypes()[0] == byte[].class
                        && method.getReturnType() == byte[].class) {
                    candidate = method;
                    break;
                }
            }
            if (candidate == null) {
                return null;
            }
            candidate.setAccessible(true);
            Object result = candidate.invoke(insertionPoint, new Object[] { payload });
            return result instanceof byte[] ? (byte[]) result : null;
        } catch (IllegalAccessException e) {
            return null;
        } catch (InvocationTargetException e) {
            return null;
        }
    }

    private static boolean rememberActiveProbe(String key) {
        if (isBlank(key)) {
            return false;
        }
        if (ACTIVE_PROBE_KEYS.size() >= MAX_ACTIVE_DEDUP_KEYS) {
            ACTIVE_PROBE_KEYS.clear();
        }
        return ACTIVE_PROBE_KEYS.putIfAbsent(key, Boolean.TRUE) == null;
    }

    private static String buildProbeKey(IRequestInfo requestInfo, IScannerInsertionPoint insertionPoint) {
        URL url = requestInfo == null ? null : requestInfo.getUrl();
        String pointClass = insertionPoint == null ? "" : insertionPoint.getClass().getName();
        return String.valueOf(url) + "|" + safeUpper(requestInfo == null ? "" : requestInfo.getMethod())
                + "|" + pointClass + "|" + insertionPointName(insertionPoint);
    }

    private static String insertionPointName(IScannerInsertionPoint insertionPoint) {
        if (insertionPoint == null) {
            return "";
        }
        try {
            Method method = insertionPoint.getClass().getMethod("getInsertionPointName");
            Object value = method.invoke(insertionPoint);
            return value == null ? "" : String.valueOf(value);
        } catch (ReflectiveOperationException ignored) {
            // The stripped legacy API bundled by this extension does not declare this method.
            return "";
        }
    }

    private static IExtensionHelpers getHelpers(BurpExtender extender) throws Exception {
        Object helpers = privateField(extender.getClass(), "helpers").get(extender);
        return helpers instanceof IExtensionHelpers ? (IExtensionHelpers) helpers : null;
    }

    private static IBurpExtenderCallbacks getCallbacks(BurpExtender extender) throws Exception {
        Object callbacks = privateField(extender.getClass(), "callbacks").get(extender);
        return callbacks instanceof IBurpExtenderCallbacks ? (IBurpExtenderCallbacks) callbacks : null;
    }

    private static Object invokeLegacy(BurpExtender extender, String name,
                                       Class<?>[] types, Object[] arguments) throws Exception {
        Method method = publicMethod(extender.getClass(), name, types);
        try {
            return method.invoke(extender, arguments);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw new IllegalStateException(cause == null ? e : cause);
        }
    }

    private static Method publicMethod(Class<?> type, String name, Class<?>... parameterTypes)
            throws NoSuchMethodException {
        String key = type.getName() + "#public#" + name + Arrays.toString(parameterTypes);
        Method existing = METHOD_CACHE.get(key);
        if (existing != null) {
            return existing;
        }
        Method created = type.getMethod(name, parameterTypes);
        created.setAccessible(true);
        METHOD_CACHE.putIfAbsent(key, created);
        return created;
    }

    private static Method privateMethod(Class<?> type, String name, Class<?>... parameterTypes)
            throws NoSuchMethodException {
        String key = type.getName() + "#private#" + name + Arrays.toString(parameterTypes);
        Method existing = METHOD_CACHE.get(key);
        if (existing != null) {
            return existing;
        }
        Class<?> current = type;
        while (current != null) {
            try {
                Method created = current.getDeclaredMethod(name, parameterTypes);
                created.setAccessible(true);
                METHOD_CACHE.putIfAbsent(key, created);
                return created;
            } catch (NoSuchMethodException ignored) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchMethodException(type.getName() + "#" + name);
    }

    private static Field privateField(Class<?> type, String name) throws NoSuchFieldException {
        String key = type.getName() + "#field#" + name;
        Field existing = FIELD_CACHE.get(key);
        if (existing != null) {
            return existing;
        }
        Class<?> current = type;
        while (current != null) {
            try {
                Field created = current.getDeclaredField(name);
                created.setAccessible(true);
                FIELD_CACHE.putIfAbsent(key, created);
                return created;
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(type.getName() + "#" + name);
    }

    private static String readStringField(Object instance, String name) throws Exception {
        Field field = privateField(instance.getClass(), name);
        Object value = field.get(instance);
        return value == null ? "" : String.valueOf(value);
    }

    private static List<IScanIssue> deduplicate(List<IScanIssue> input) {
        if (input == null || input.isEmpty()) {
            return Collections.emptyList();
        }
        Map<String, IScanIssue> unique = new LinkedHashMap<String, IScanIssue>();
        for (IScanIssue issue : input) {
            if (issue == null) {
                continue;
            }
            String key = safe(issue.getIssueName()) + "|" + safe(issue.getSeverity()) + "|"
                    + String.valueOf(issue.getUrl());
            unique.put(key, issue);
        }
        return new ArrayList<IScanIssue>(unique.values());
    }

    private static void appendAll(List<IScanIssue> destination, List<IScanIssue> source) {
        if (source != null && !source.isEmpty()) {
            destination.addAll(source);
        }
    }

    private static boolean isLowOrInformation(String risk) {
        String normalized = safe(risk).trim().toLowerCase(Locale.ROOT);
        return "low".equals(normalized) || "information".equals(normalized)
                || "info".equals(normalized) || "低".equals(normalized)
                || "信息".equals(normalized) || "信息级".equals(normalized);
    }

    private static String toBurpSeverity(String risk) {
        String normalized = safe(risk).trim().toLowerCase(Locale.ROOT);
        if ("高".equals(normalized) || "high".equals(normalized)) {
            return "High";
        }
        if ("中".equals(normalized) || "medium".equals(normalized)) {
            return "Medium";
        }
        if ("低".equals(normalized) || "low".equals(normalized)) {
            return "Low";
        }
        return "Information";
    }

    private static String stripOptionalQuotes(String value) {
        if (value != null && value.length() >= 2) {
            char first = value.charAt(0);
            char last = value.charAt(value.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return value.substring(1, value.length() - 1);
            }
        }
        return value == null ? "" : value;
    }

    private static String safeUpper(String value) {
        return safe(value).trim().toUpperCase(Locale.ROOT);
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().length() == 0;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static String emptyFallback(String value, String fallback) {
        return isBlank(value) ? fallback : value;
    }

    private static String safeMessage(Exception e) {
        String message = e.getMessage();
        return message == null ? e.getClass().getSimpleName() : message;
    }

    private static void log(BurpExtender extender, String line) {
        try {
            if (extender != null && extender.stdout != null) {
                extender.stdout.println(line);
            }
        } catch (RuntimeException ignored) {
            // Logging must never interfere with Burp's listener thread.
        }
    }



    /** Minimal local issue type so low/info and active evidence do not depend on private inner classes. */
    private static final class EnhancedScanIssue implements IScanIssue {
        private final IHttpService httpService;
        private final URL url;
        private final IHttpRequestResponse[] messages;
        private final String name;
        private final String severity;
        private final String confidence;
        private final String detail;

        private EnhancedScanIssue(IHttpService httpService, URL url,
                                  IHttpRequestResponse[] messages, String name,
                                  String severity, String confidence, String detail) {
            this.httpService = httpService;
            this.url = url;
            this.messages = messages == null ? new IHttpRequestResponse[0] : messages.clone();
            this.name = name == null ? "[CGN] Finding" : name;
            this.severity = severity == null ? "Information" : severity;
            this.confidence = confidence == null ? "Tentative" : confidence;
            this.detail = detail == null ? "" : detail;
        }

        public URL getUrl() { return url; }
        public String getIssueName() { return name; }
        public int getIssueType() { return 0; }
        public String getSeverity() { return severity; }
        public String getConfidence() { return confidence; }
        public String getIssueBackground() { return null; }
        public String getRemediationBackground() { return null; }
        public String getIssueDetail() { return detail; }
        public String getRemediationDetail() { return null; }
        public IHttpRequestResponse[] getHttpMessages() { return messages.clone(); }
        public IHttpService getHttpService() { return httpService; }
    }

}
