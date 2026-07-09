package burp.config;

import burp.RuleLibraryRepository;
import burp.dictionary.LayeredDictionaryStore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
/**
 * Immutable copy of every legacy Swing-backed value consumed by scan workers.
 * Instances are created only on the EDT and published through AtomicReference.
 */
public final class UiScanSnapshot {
    public static final int DEFAULT_INTERVAL_MS = 500;

    public final boolean pluginEnabled;
    public final boolean directoryScanEnabled;
    public final boolean scanPaused;
    public final boolean whiteListEnabled;
    public final String whiteListRules;
    public final boolean blackListEnabled;
    public final String blackListRules;
    public final String denyTokens;
    public final int intervalMillis;
    public final boolean level0Enabled;
    public final boolean level1Enabled;
    public final boolean level2Enabled;
    public final boolean level3Enabled;
    public final boolean level4Enabled;
    public final List<String> extraHeaders;
    public final RuleLibraryRepository.RuleSnapshot ruleSnapshot;

    public UiScanSnapshot(boolean pluginEnabled,
                   boolean directoryScanEnabled,
                   boolean scanPaused,
                   boolean whiteListEnabled,
                   String whiteListRules,
                   boolean blackListEnabled,
                   String blackListRules,
                   String denyTokens,
                   int intervalMillis,
                   boolean level0Enabled,
                   boolean level1Enabled,
                   boolean level2Enabled,
                   boolean level3Enabled,
                   boolean level4Enabled,
                   List<String> extraHeaders,
                   RuleLibraryRepository.RuleSnapshot ruleSnapshot) {
        this.pluginEnabled = pluginEnabled;
        this.directoryScanEnabled = directoryScanEnabled;
        this.scanPaused = scanPaused;
        this.whiteListEnabled = whiteListEnabled;
        this.whiteListRules = safe(whiteListRules);
        this.blackListEnabled = blackListEnabled;
        this.blackListRules = safe(blackListRules);
        this.denyTokens = safe(denyTokens);
        this.intervalMillis = Math.max(50, intervalMillis);
        this.level0Enabled = level0Enabled;
        this.level1Enabled = level1Enabled;
        this.level2Enabled = level2Enabled;
        this.level3Enabled = level3Enabled;
        this.level4Enabled = level4Enabled;
        this.extraHeaders = Collections.unmodifiableList(new ArrayList<String>(
                extraHeaders == null ? Collections.<String>emptyList() : extraHeaders));
        this.ruleSnapshot = ruleSnapshot == null ? emptyRules() : ruleSnapshot;
    }

    public static UiScanSnapshot disabled() {
        return new UiScanSnapshot(false, false, false, false, "", false, "", "",
                DEFAULT_INTERVAL_MS, false, false, false, false, false,
                Collections.<String>emptyList(), emptyRules());
    }

    public boolean levelEnabled(int level) {
        switch (level) {
            case 0: return level0Enabled;
            case 1: return level1Enabled;
            case 2: return level2Enabled;
            case 3: return level3Enabled;
            case 4: return level4Enabled;
            default: return false;
        }
    }

    public boolean sameContent(UiScanSnapshot that) {
        if (that == null) return false;
        return pluginEnabled == that.pluginEnabled
                && directoryScanEnabled == that.directoryScanEnabled
                && scanPaused == that.scanPaused
                && whiteListEnabled == that.whiteListEnabled
                && blackListEnabled == that.blackListEnabled
                && intervalMillis == that.intervalMillis
                && level0Enabled == that.level0Enabled
                && level1Enabled == that.level1Enabled
                && level2Enabled == that.level2Enabled
                && level3Enabled == that.level3Enabled
                && level4Enabled == that.level4Enabled
                && Objects.equals(whiteListRules, that.whiteListRules)
                && Objects.equals(blackListRules, that.blackListRules)
                && Objects.equals(denyTokens, that.denyTokens)
                && Objects.equals(extraHeaders, that.extraHeaders)
                && Objects.equals(ruleSnapshot.version(), that.ruleSnapshot.version());
    }

    private static RuleLibraryRepository.RuleSnapshot emptyRules() {
        return new RuleLibraryRepository.RuleSnapshot(Collections.<String>emptyList(),
                Collections.<Object>emptyList(), Collections.<LayeredDictionaryStore.DictionaryGroup>emptyList(), "empty");
    }

    private static String safe(String input) {
        return input == null ? "" : input;
    }
}
