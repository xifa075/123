package burp.scan;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import java.lang.reflect.Method;
import java.net.URL;

/** Scope boundary helper. Keeps Burp Scope decisions out of task planning code. */
public final class ScopeGuard {
    private ScopeGuard() { }

    public static boolean isAllowed(BurpExtender extender, IBurpExtenderCallbacks callbacks,
                                    URL url, boolean scopeRequired) {
        if (!scopeRequired) return true;
        if (url == null || callbacks == null) return false;
        try {
            Method method = callbacks.getClass().getMethod("isInScope", URL.class);
            Object value = method.invoke(callbacks, url);
            return Boolean.TRUE.equals(value);
        } catch (NoSuchMethodException missing) {
            return false;
        } catch (Exception error) {
            try {
                if (extender != null && extender.stdout != null) {
                    extender.stdout.println("[CGN] Burp Scope check failed: " + error.getMessage());
                }
            } catch (Exception ignored) { }
            return false;
        }
    }
}
