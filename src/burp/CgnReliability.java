package burp;

import burp.config.ScanConfig;
import burp.scan.RetryPolicy;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Reliability layer for the static V5.6.1 bytecode patch.
 *
 * This scheduler deliberately does not call the legacy scan_uri() method, because its legacy
 * deduplication and budget bookkeeping are committed before a request has been built or has a
 * usable response. It uses the original request builder, classifiers and result model through
 * narrow reflective seams so the existing templates, dictionary, risk logic and result UI remain
 * compatible.
 */
public final class CgnReliability {

    public static final int WORKER_THREADS = 2;
    public static final int HARD_MAX_PENDING = 1000;
    public static final int HARD_MAX_DEFERRED = 5000;
    public static final int HARD_MAX_TASK_RECORDS = 8000;
    public static final int HARD_MAX_COMPLETED_KEYS = 10000;
    public static final int UI_REFRESH_MIN_INTERVAL_MS = 500;

    private static final Map<BurpExtender, ScanOrchestrator> ORCHESTRATORS =
            Collections.synchronizedMap(new WeakHashMap<BurpExtender, ScanOrchestrator>());
    private static final ConcurrentMap<String, Method> METHOD_CACHE =
            new ConcurrentHashMap<String, Method>();
    private static final ConcurrentMap<String, Field> FIELD_CACHE =
            new ConcurrentHashMap<String, Field>();
    private static final AtomicBoolean SCOPE_API_WARNING_EMITTED = new AtomicBoolean(false);

    private CgnReliability() { }

    public static void registerExtenderCallbacks(BurpExtender extender, IBurpExtenderCallbacks callbacks) {
        try {
            invokeLegacy(extender, "cgn$registerExtenderCallbacksLegacy",
                    new Class<?>[] { IBurpExtenderCallbacks.class }, new Object[] { callbacks });
            ScanOrchestrator orchestrator = forExtender(extender);
            orchestrator.install(callbacks);
            log(extender, "[CGN] 可靠性调度器已启用：任务状态、失败重试、延迟队列、Scope 与右键扫描入口已加载。");
        } catch (Exception e) {
            log(extender, "[CGN] 初始化可靠性调度器失败，已保留原始插件行为: " + safeMessage(e));
            try {
                invokeLegacy(extender, "cgn$registerExtenderCallbacksLegacy",
                        new Class<?>[] { IBurpExtenderCallbacks.class }, new Object[] { callbacks });
            } catch (Exception legacyFailure) {
                log(extender, "[CGN] 原始初始化同样失败: " + safeMessage(legacyFailure));
            }
        }
    }

    public static void extensionUnloaded(BurpExtender extender) {
        ScanOrchestrator orchestrator;
        synchronized (ORCHESTRATORS) {
            orchestrator = ORCHESTRATORS.remove(extender);
        }
        if (orchestrator != null) {
            orchestrator.shutdown();
        }
        try {
            invokeLegacy(extender, "cgn$extensionUnloadedLegacy", new Class<?>[0], new Object[0]);
        } catch (Exception e) {
            log(extender, "[CGN] 原始卸载清理失败: " + safeMessage(e));
        }
    }

    public static void processHttpMessage(BurpExtender extender, int toolFlag,
                                   boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest || messageInfo == null) {
            return;
        }
        forExtender(extender).enqueueAutomatic(toolFlag, messageInfo);
    }

    /** Returns false before the reliability layer has finished installing legacy UI bindings. */
    public static boolean requestResultViewRefresh(BurpExtender extender, boolean filterChanged) {
        ScanOrchestrator orchestrator;
        synchronized (ORCHESTRATORS) { orchestrator = ORCHESTRATORS.get(extender); }
        if (orchestrator == null) return false;
        orchestrator.requestResultViewRefresh(filterChanged);
        return true;
    }

    private static final ConcurrentMap<String, Boolean> ACTIVE_PROBE_IN_FLIGHT =
            new ConcurrentHashMap<String, Boolean>();
    private static final ConcurrentMap<String, Boolean> ACTIVE_PROBE_COMPLETED =
            new ConcurrentHashMap<String, Boolean>();

    public static boolean isActiveScopeAllowed(BurpExtender extender, IBurpExtenderCallbacks callbacks, URL url) {
        return isScopeAllowed(extender, callbacks, url, forExtender(extender).scopeRequired());
    }

    public static boolean claimActiveProbe(String key) {
        if (isBlank(key) || ACTIVE_PROBE_COMPLETED.containsKey(key)) {
            return false;
        }
        return ACTIVE_PROBE_IN_FLIGHT.putIfAbsent(key, Boolean.TRUE) == null;
    }

    public static void completeActiveProbe(String key) {
        ACTIVE_PROBE_IN_FLIGHT.remove(key);
        ACTIVE_PROBE_COMPLETED.put(key, Boolean.TRUE);
        if (ACTIVE_PROBE_COMPLETED.size() > HARD_MAX_COMPLETED_KEYS) {
            ACTIVE_PROBE_COMPLETED.clear();
        }
    }

    public static void releaseActiveProbe(String key) {
        ACTIVE_PROBE_IN_FLIGHT.remove(key);
    }

    public static IHttpRequestResponse executeSafeActiveProbe(BurpExtender extender,
                                                        IBurpExtenderCallbacks callbacks,
                                                        IHttpService service, byte[] request,
                                                        String key) {
        if (callbacks == null || service == null || request == null || request.length == 0) {
            return null;
        }
        ScanConfig settings = forExtender(extender).config();
        RuntimeException last = null;
        for (int attempt = 0; attempt <= settings.maxRetries; attempt++) {
            try {
                IHttpRequestResponse response = callbacks.makeHttpRequest(service, request);
                if (response != null && response.getResponse() != null) {
                    return response;
                }
            } catch (RuntimeException error) {
                last = error;
            }
            if (attempt < settings.maxRetries) {
                sleepRespectingInterrupt((int) retryDelay(settings, attempt + 1));
            }
        }
        log(extender, "[CGN] 主动探针未获得有效响应，已释放去重锁供后续重试"
                + (last == null ? "" : ": " + safeMessage(last)));
        return null;
    }

    public static boolean isScopeAllowed(BurpExtender extender, IBurpExtenderCallbacks callbacks, URL url,
                                  boolean scopeRequired) {
        if (!scopeRequired || url == null || callbacks == null) {
            return !scopeRequired || url != null;
        }
        try {
            Method scopeMethod = method(callbacks.getClass(), "isInScope", new Class<?>[] { URL.class }, false);
            Object result = scopeMethod.invoke(callbacks, url);
            return Boolean.TRUE.equals(result);
        } catch (NoSuchMethodException e) {
            if (SCOPE_API_WARNING_EMITTED.compareAndSet(false, true)) {
                log(extender, "[CGN] 当前 Burp 回调未暴露 isInScope(URL)：为避免越界，已拒绝自动/右键扫描。"
                        + "若确认运行环境不支持 Scope API，请在“可靠性”页显式关闭 Scope 强制。");
            }
            return false;
        } catch (Exception e) {
            log(extender, "[CGN] Scope 校验失败，已拒绝本次扫描: " + safeMessage(e));
            return false;
        }
    }

    private static ScanOrchestrator forExtender(BurpExtender extender) {
        synchronized (ORCHESTRATORS) {
            ScanOrchestrator result = ORCHESTRATORS.get(extender);
            if (result == null) {
                result = new ScanOrchestrator(extender);
                ORCHESTRATORS.put(extender, result);
            }
            return result;
        }
    }

    private static Object invokeLegacy(BurpExtender extender, String name, Class<?>[] types,
                                       Object[] arguments) throws Exception {
        return invokeNamed(extender, name, types, arguments, true);
    }

    public static Object invokePrivate(BurpExtender extender, String name, Class<?>[] types,
                                        Object[] arguments) throws Exception {
        return invokeNamed(extender, name, types, arguments, false);
    }

    public static Object invokeNamed(BurpExtender extender, String name, Class<?>[] types,
                                      Object[] arguments, boolean publicMethod) throws Exception {
        Method method = method(extender.getClass(), name, types, publicMethod);
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

    public static Method method(Class<?> type, String name, Class<?>[] types, boolean publicMethod)
            throws NoSuchMethodException {
        String key = type.getName() + "#" + (publicMethod ? "pub" : "priv") + "#" + name
                + Arrays.toString(types);
        Method cached = METHOD_CACHE.get(key);
        if (cached != null) {
            return cached;
        }
        Method found;
        if (publicMethod) {
            found = type.getMethod(name, types);
        } else {
            Class<?> cursor = type;
            found = null;
            while (cursor != null) {
                try {
                    found = cursor.getDeclaredMethod(name, types);
                    break;
                } catch (NoSuchMethodException ignored) {
                    cursor = cursor.getSuperclass();
                }
            }
            if (found == null) {
                throw new NoSuchMethodException(type.getName() + "#" + name);
            }
        }
        found.setAccessible(true);
        METHOD_CACHE.putIfAbsent(key, found);
        return found;
    }

    public static Object readField(Object instance, String name) throws Exception {
        Field field = field(instance.getClass(), name);
        return field.get(instance);
    }

    public static Field field(Class<?> type, String name) throws NoSuchFieldException {
        String key = type.getName() + "#field#" + name;
        Field cached = FIELD_CACHE.get(key);
        if (cached != null) {
            return cached;
        }
        Class<?> cursor = type;
        while (cursor != null) {
            try {
                Field found = cursor.getDeclaredField(name);
                found.setAccessible(true);
                FIELD_CACHE.putIfAbsent(key, found);
                return found;
            } catch (NoSuchFieldException ignored) {
                cursor = cursor.getSuperclass();
            }
        }
        throw new NoSuchFieldException(type.getName() + "#" + name);
    }

    public static String fieldString(Object instance, String fieldName) throws Exception {
        Object value = field(instance.getClass(), fieldName).get(instance);
        return value == null ? "" : String.valueOf(value);
    }

    public static String fieldStringQuietly(Object instance, String fieldName) {
        try {
            return fieldString(instance, fieldName);
        } catch (Exception e) {
            return "";
        }
    }

    public static int intValue(Object value) {
        return value instanceof Number ? ((Number) value).intValue() : 0;
    }



    public static List<String> buildAncestorDirectories(URL url) {
        String path = url == null ? "/" : safe(url.getPath());
        if (path.length() == 0 || "/".equals(path)) {
            return Collections.singletonList("/");
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        while (normalized.contains("//")) {
            normalized = normalized.replace("//", "/");
        }
        boolean hasFileLikeTail = normalized.lastIndexOf('/') < normalized.length() - 1;
        String directoryPortion = hasFileLikeTail
                ? normalized.substring(0, normalized.lastIndexOf('/') + 1) : normalized;
        if (directoryPortion.length() == 0) {
            directoryPortion = "/";
        }
        List<String> directories = new ArrayList<String>();
        directories.add("/");
        String[] pieces = directoryPortion.split("/");
        StringBuilder current = new StringBuilder();
        for (String piece : pieces) {
            if (piece.length() == 0) {
                continue;
            }
            current.append('/').append(piece);
            String item = current.toString() + "/";
            if (!directories.contains(item)) {
                directories.add(item);
            }
        }
        return directories;
    }

    public static String joinPath(String parent, String entry) {
        String normalizedParent = isBlank(parent) ? "/" : parent;
        String normalizedEntry = safe(entry).trim();
        if (!normalizedParent.startsWith("/")) {
            normalizedParent = "/" + normalizedParent;
        }
        if (!normalizedParent.endsWith("/")) {
            normalizedParent += "/";
        }
        while (normalizedEntry.startsWith("/")) {
            normalizedEntry = normalizedEntry.substring(1);
        }
        return normalizedParent + normalizedEntry;
    }

    public static String canonicalBasePath(URL url) {
        if (url == null) {
            return "";
        }
        return originFor(url) + safe(url.getPath());
    }

    public static String originFor(URL url) {
        if (url == null) {
            return "";
        }
        int port = url.getPort();
        boolean defaultPort = ("http".equalsIgnoreCase(url.getProtocol()) && port == 80)
                || ("https".equalsIgnoreCase(url.getProtocol()) && port == 443) || port < 0;
        return url.getProtocol() + "://" + url.getHost() + (defaultPort ? "" : ":" + port);
    }

    public static void sleepRespectingInterrupt(int millis) {
        try {
            Thread.sleep(Math.max(50, millis));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    public static long retryDelay(ScanConfig settings, int attempt) {
        return RetryPolicy.backoffMillis(settings, attempt);
    }

    public static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    public static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(safe(input).getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte value : bytes) {
                hex.append(String.format(Locale.ROOT, "%02x", value & 0xff));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException impossible) {
            return Integer.toHexString(safe(input).hashCode()) + "0000000000000000";
        }
    }

    public static boolean isBlank(String value) {
        return value == null || value.trim().length() == 0;
    }

    public static String safe(String value) {
        return value == null ? "" : value;
    }

    public static String safeMessage(Exception error) {
        String message = error.getMessage();
        return message == null ? error.getClass().getSimpleName() : message;
    }

    public static void log(BurpExtender extender, String message) {
        try {
            if (extender != null && extender.stdout != null) {
                extender.stdout.println(message);
            }
        } catch (RuntimeException ignored) {
            // Logging must never break a Burp listener/worker.
        }
    }
}
