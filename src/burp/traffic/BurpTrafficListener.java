package burp.traffic;

import burp.BurpExtender;
import burp.CgnReliability;
import burp.IHttpRequestResponse;
/** Burp traffic boundary. It accepts only response events and delegates scheduling decisions. */
public final class BurpTrafficListener {
    private BurpTrafficListener() { }
    public static void onHttpMessage(BurpExtender extender, int toolFlag, boolean messageIsRequest,
                              IHttpRequestResponse message) {
        if (messageIsRequest || message == null) return;
        CgnReliability.processHttpMessage(extender, toolFlag, false, message);
    }
}
