package burp.request;

import burp.BurpExtensionAccess;
import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.config.ScanConfig;
import burp.config.UiScanSnapshot;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
/** Pure request builder: it consumes immutable snapshots and never reads Swing or legacy UI fields. */
public final class RequestBuilder {
    public RequestBuilder(BurpExtender extender) { }

    public boolean isGroupEnabledAtLevel(Object group, int level, UiScanSnapshot snapshot) {
        if (group == null) return snapshot != null && snapshot.levelEnabled(level);
        return BurpExtensionAccess.readBooleanField(group, "level" + level);
    }

    /**
     * Safety guard for configuration workflow. GET / HEAD / OPTIONS remain available by default;
     * methods that may create, modify or delete state require a deliberate persisted opt-in.
     */
    public boolean isMethodAllowed(Object group, ScanConfig settings) {
        String method = groupMethod(group);
        if ("GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method)) return true;
        return settings != null && settings.unsafeTemplateMethodsAllowed;
    }

    public String groupMethod(Object group) {
        String method = BurpExtensionAccess.readStringField(group, "method").trim();
        return method.length() == 0 ? "GET" : method.toUpperCase(Locale.ROOT);
    }

    public String buildTarget(String candidate, String parent, Object group) {
        String groupPath = BurpExtensionAccess.readStringField(group, "path").trim();
        if (groupPath.length() == 0) return normalizePath(candidate);
        String normalizedTemplate = normalizePath(groupPath);
        String normalizedParent = normalizePath(parent);
        if ("/".equals(normalizedParent)) return normalizedTemplate;
        return trimTrailingSlash(normalizedParent) + normalizedTemplate;
    }

    public byte[] buildRequest(IExtensionHelpers helpers, IRequestInfo baseInfo, String target,
                        Object group, List<String> extraHeaders, ScanConfig settings) {
        if (helpers == null || baseInfo == null || target == null) return null;
        if (!isMethodAllowed(group, settings)) return null;
        String method = groupMethod(group);
        String bodyText = BurpExtensionAccess.readStringField(group, "body");
        boolean jsonBody = looksLikeJson(bodyText);
        List<String> headers = new ArrayList<String>();
        headers.add(method + " " + target + " HTTP/1.1");
        headers.add("Host: " + hostHeader(baseInfo.getUrl()));

        boolean contentTypePresent = false;
        List<String> baseHeaders = baseInfo.getHeaders();
        if (baseHeaders != null) {
            for (int i = 1; i < baseHeaders.size(); i++) {
                String line = baseHeaders.get(i);
                String lower = line == null ? "" : line.toLowerCase(Locale.ROOT);
                if (lower.startsWith("host:") || lower.startsWith("content-length:")) continue;
                if (lower.startsWith("content-type:")) {
                    if (jsonBody) continue;
                    contentTypePresent = true;
                }
                if (line != null) headers.add(line);
            }
        }
        if (extraHeaders != null) {
            for (String raw : extraHeaders) {
                String line = raw == null ? "" : raw.trim();
                String name = headerName(line);
                if (name.length() == 0) continue;
                String lower = name.toLowerCase(Locale.ROOT);
                if ("host".equals(lower) || "content-length".equals(lower)) continue;
                removeExistingHeader(headers, name);
                if ("content-type".equals(lower)) contentTypePresent = true;
                headers.add(line);
            }
        }

        byte[] body = new byte[0];
        if (methodAllowsBody(method) && bodyText != null && bodyText.length() > 0) {
            body = helpers.stringToBytes(bodyText);
            if (!contentTypePresent) {
                headers.add(jsonBody ? "Content-Type: application/json"
                        : "Content-Type: application/x-www-form-urlencoded");
            }
        }
        return helpers.buildHttpMessage(headers, body);
    }

    public boolean containsDeniedToken(String path, String tokens) {
        if (tokens == null || tokens.trim().isEmpty()) return false;
        for (String token : tokens.split(",")) {
            String value = token.trim();
            if (!value.isEmpty() && path != null && path.contains(value)) return true;
        }
        return false;
    }

    private static String hostHeader(URL url) {
        if (url == null) return "";
        String host = url.getHost() == null ? "" : url.getHost();
        int port = url.getPort();
        int defaultPort = url.getDefaultPort();
        return port > 0 && port != defaultPort ? host + ":" + port : host;
    }

    private static boolean methodAllowsBody(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
    }

    private static boolean looksLikeJson(String body) {
        String trimmed = body == null ? "" : body.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}"))
                || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    private static String normalizePath(String path) {
        String value = path == null ? "/" : path.trim();
        if (value.length() == 0) return "/";
        return value.startsWith("/") ? value : "/" + value;
    }

    private static String trimTrailingSlash(String value) {
        String output = value;
        while (output.length() > 1 && output.endsWith("/")) output = output.substring(0, output.length() - 1);
        return output;
    }

    private static String headerName(String header) {
        int index = header.indexOf(':');
        return index <= 0 ? "" : header.substring(0, index).trim();
    }

    private static void removeExistingHeader(List<String> headers, String headerName) {
        for (int i = headers.size() - 1; i >= 1; i--) {
            String existing = headers.get(i);
            if (headerName.equalsIgnoreCase(headerName(existing))) headers.remove(i);
        }
    }
}
