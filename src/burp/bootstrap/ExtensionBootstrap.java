package burp.bootstrap;

import burp.BurpExtender;
import burp.CgnReliability;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.traffic.BurpTrafficListener;
/** Composition root for Burp lifecycle events. */
public final class ExtensionBootstrap {
    private ExtensionBootstrap() { }
    public static void register(BurpExtender extender, IBurpExtenderCallbacks callbacks) {
        CgnReliability.registerExtenderCallbacks(extender, callbacks);
    }
    public static void unload(BurpExtender extender) { CgnReliability.extensionUnloaded(extender); }
    public static void onHttpMessage(BurpExtender extender, int toolFlag, boolean request,
                              IHttpRequestResponse message) {
        BurpTrafficListener.onHttpMessage(extender, toolFlag, request, message);
    }
}
