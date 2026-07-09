package burp.scan;

import burp.CgnReliability;
import burp.dictionary.LayeredDictionaryStore;
import burp.request.RequestBuilder;

import java.util.ArrayList;
import java.util.List;

/** Pure path/template planning helpers shared by reliable scan execution. */
public final class ScanPathPlanner {
    private ScanPathPlanner() { }

    public static List<Object> eligibleTemplatesFor(ScanPlan plan,
                                                     LayeredDictionaryStore.DictionaryGroup dictionaryGroup,
                                                     int level,
                                                     RequestBuilder requestBuilder) {
        List<Object> eligible = new ArrayList<Object>();
        for (Object group : plan.requestGroups) {
            if (!dictionaryGroup.matchesTemplate(group)) {
                continue;
            }
            if (!requestBuilder.isGroupEnabledAtLevel(group, level, plan.uiSnapshot)) {
                continue;
            }
            if (!requestBuilder.isMethodAllowed(group, plan.settings)) {
                continue;
            }
            eligible.add(group);
        }
        return eligible;
    }

    public static String resolveDictionaryBaseDirectory(List<String> ancestors, int level,
                                                        LayeredDictionaryStore.PathStrategy strategy) {
        if (strategy == LayeredDictionaryStore.PathStrategy.ROOT
                || strategy == LayeredDictionaryStore.PathStrategy.ABSOLUTE) {
            return "/";
        }
        if (strategy == LayeredDictionaryStore.PathStrategy.PARENT) {
            return level <= 0 ? "/" : ancestors.get(Math.max(0, level - 1));
        }
        return ancestors.get(Math.max(0, Math.min(level, ancestors.size() - 1)));
    }

    public static String buildDictionaryCandidate(String baseDirectory, String entry,
                                                  LayeredDictionaryStore.PathStrategy strategy) {
        String normalizedEntry = CgnReliability.safe(entry).trim();
        if (strategy == LayeredDictionaryStore.PathStrategy.ABSOLUTE) {
            while (normalizedEntry.startsWith("/")) {
                normalizedEntry = normalizedEntry.substring(1);
            }
            return CgnReliability.joinPath("/", normalizedEntry);
        }
        return CgnReliability.joinPath(baseDirectory, normalizedEntry);
    }

    public static String buildProbeKey(ScanPlan plan, String target, Object group) {
        return buildProbeKey(plan, target, group, null);
    }

    public static String buildProbeKey(ScanPlan plan, String target, Object group,
                                       LayeredDictionaryStore.DictionaryGroup dictionaryGroup) {
        String dictionaryPart = dictionaryGroup == null ? "" : (dictionaryGroup.id + ":" + dictionaryGroup.levelText());
        return plan.normalizedHost + "|" + target + "|" + CgnReliability.fieldStringQuietly(group, "name")
                + "|" + CgnReliability.fieldStringQuietly(group, "method") + "|" + plan.templateVersion
                + "|dict=" + dictionaryPart;
    }
}
