package burp.js;

import burp.BurpExtensionAccess;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
/** Delegates content parsing to the original implementation without allowing it into scheduler code. */
public final class JsExtractionEngine {
    private final BurpExtender extender;
    public JsExtractionEngine(BurpExtender extender) { this.extender = extender; }

    public void extract(IHttpRequestResponse message, int sourceToolFlag) throws Exception {
        BurpExtensionAccess.invokePrivate(extender, "js_analysis",
                new Class<?>[] { IHttpRequestResponse.class, int.class },
                new Object[] { message, Integer.valueOf(sourceToolFlag) });
    }
}
