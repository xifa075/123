package burp.scan;

/** Burp traffic source selected for automatic/manual scan scheduling. */
public enum ScanSource {
    TARGET(2, "Target"),
    PROXY(4, "Proxy"),
    SCANNER(16, "Scanner"),
    INTRUDER(32, "Intruder"),
    REPEATER(64, "Repeater"),
    MANUAL(0, "Manual");

    public final int toolFlag;
    public final String label;

    ScanSource(int toolFlag, String label) {
        this.toolFlag = toolFlag;
        this.label = label;
    }

    public static ScanSource fromToolFlag(int toolFlag) {
        for (ScanSource source : values()) {
            if (source.toolFlag == toolFlag) {
                return source;
            }
        }
        return null;
    }
}
