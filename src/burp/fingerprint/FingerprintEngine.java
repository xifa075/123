package burp.fingerprint;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
/** Deterministic, evidence-scoped fingerprint evaluator. */
public final class FingerprintEngine {
    private FingerprintEngine() { }

    public static boolean matches(String content, String expression) {
        if (blank(content) || blank(expression)) return false;
        EvidenceContext context = EvidenceContext.from(content);
        boolean hasPositive = false;
        int expectedWeight = 0;
        int matchedWeight = 0;
        for (String raw : splitLegacyAndClauses(expression)) {
            String clause = raw.trim();
            if (clause.isEmpty()) continue;
            if (clause.startsWith("!")) {
                String negative = clause.substring(1).trim();
                if (negative.isEmpty() || matchesOne(context, negative)) return false;
                continue;
            }
            hasPositive = true;
            int weight = evidenceWeight(clause);
            expectedWeight += weight;
            boolean matched = false;
            if (clause.contains("||")) {
                for (String alternative : clause.split("\\|\\|")) {
                    if (!alternative.trim().isEmpty() && matchesOne(context, alternative.trim())) {
                        matched = true; break;
                    }
                }
            } else matched = matchesOne(context, clause);
            if (!matched) return false;
            matchedWeight += weight;
        }
        return hasPositive && expectedWeight > 0 && matchedWeight >= expectedWeight;
    }

    private static boolean matchesOne(EvidenceContext context, String expression) {
        String candidate = expression == null ? "" : expression.trim();
        if (candidate.isEmpty()) return false;
        String source = context.all;
        String value = candidate;
        String lower = candidate.toLowerCase(Locale.ROOT);
        if (lower.startsWith("url:")) { source = context.url; value = candidate.substring(4).trim(); }
        else if (lower.startsWith("header:")) { source = context.headers; value = candidate.substring(7).trim(); }
        else if (lower.startsWith("body:")) { source = context.body; value = candidate.substring(5).trim(); }
        else if (lower.startsWith("re:")) return regex(context.all, candidate.substring(3).trim());
        return !value.isEmpty() && literal(source, value);
    }

    private static boolean literal(String source, String value) {
        if (source == null || value == null) return false;
        String haystack = source.toLowerCase(Locale.ROOT);
        String needle = unquote(value.trim()).toLowerCase(Locale.ROOT);
        if (needle.isEmpty()) return false;
        if (needle.matches("[a-z0-9_]+")) {
            return Pattern.compile("(?<![a-z0-9_])" + Pattern.quote(needle) + "(?![a-z0-9_])")
                    .matcher(haystack).find();
        }
        return haystack.contains(needle);
    }

    private static boolean regex(String source, String expression) {
        if (source == null || blank(expression) || expression.length() > 1024) return false;
        try {
            return Pattern.compile(expression, Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(source).find();
        } catch (PatternSyntaxException ignored) { return false; }
    }

    private static int evidenceWeight(String clause) {
        String lower = clause == null ? "" : clause.trim().toLowerCase(Locale.ROOT);
        return lower.startsWith("url:") || lower.startsWith("header:")
                || lower.startsWith("body:") || lower.startsWith("re:") ? 2 : 1;
    }

    private static List<String> splitLegacyAndClauses(String expression) {
        List<String> values = new ArrayList<String>();
        StringBuilder current = new StringBuilder();
        for (int index = 0; index < expression.length(); index++) {
            char ch = expression.charAt(index);
            if (ch == '\r') continue;
            if (ch == '\n') { values.add(current.toString()); current.setLength(0); continue; }
            if (ch == '|') {
                boolean previous = index > 0 && expression.charAt(index - 1) == '|';
                boolean next = index + 1 < expression.length() && expression.charAt(index + 1) == '|';
                if (!previous && !next) { values.add(current.toString()); current.setLength(0); continue; }
            }
            current.append(ch);
        }
        values.add(current.toString());
        return values;
    }

    private static String unquote(String value) {
        if (value.length() >= 2 && ((value.startsWith("\"") && value.endsWith("\""))
                || (value.startsWith("'") && value.endsWith("'")))) return value.substring(1, value.length() - 1);
        return value;
    }
    private static boolean blank(String value) { return value == null || value.trim().isEmpty(); }

    private static final class EvidenceContext {
        final String all; final String url; final String headers; final String body;
        EvidenceContext(String all, String url, String headers, String body) {
            this.all = all; this.url = url; this.headers = headers; this.body = body;
        }
        static EvidenceContext from(String combined) {
            String value = combined == null ? "" : combined;
            int first = value.indexOf('\n');
            if (first < 0) return new EvidenceContext(value, value, "", "");
            int second = value.indexOf('\n', first + 1);
            if (second < 0) return new EvidenceContext(value, value.substring(0, first),
                    value.substring(first + 1), "");
            return new EvidenceContext(value, value.substring(0, first),
                    value.substring(first + 1, second), value.substring(second + 1));
        }
    }
}
