package burp.dictionary;

import burp.BurpExtensionAccess;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.UUID;
/**
 * Persistent layered dictionary model. It is deliberately independent from the legacy
 * path dictionary so that old projects keep working while advanced users can opt in
 * to depth-aware dictionary groups.
 */
public final class LayeredDictionaryStore {
    public static final int MIN_LEVEL = 0;
    public static final int MAX_LEVEL = 8;
    public static final int DEFAULT_MAX_REQUESTS = 1000;
    public static final int MAX_GROUPS = 80;
    public static final int MAX_ENTRIES_PER_GROUP = 5000;
    public static final int MAX_IMPORT_BYTES = 2 * 1024 * 1024;

    private static final File FILE = new File("cgn_layered_dictionaries.properties");

    public enum PathStrategy {
        CURRENT("当前目录拼接"),
        ROOT("根路径拼接"),
        PARENT("父目录拼接"),
        ABSOLUTE("绝对路径/根路径");

        public final String label;
        PathStrategy(String label) { this.label = label; }

        static PathStrategy parse(String value) {
            if (value == null) return CURRENT;
            String text = value.trim().toUpperCase(Locale.ROOT);
            for (PathStrategy strategy : values()) {
                if (strategy.name().equals(text) || strategy.label.equals(value)) return strategy;
            }
            return CURRENT;
        }
    }

    public static final class DictionaryGroup {
        public final String id;
        public final String name;
        public final boolean enabled;
        public final int minLevel;
        public final int maxLevel;
        public final PathStrategy strategy;
        public final String templateName;
        /** Optional maintenance metadata for team-owned dictionary groups. */
        public final String category;
        public final String tags;
        public final String version;
        public final String description;
        public final long updatedAt;
        public final int priority;
        public final int maxRequests;
        public final List<String> entries;
        public final boolean legacyFallback;

        public DictionaryGroup(String id, String name, boolean enabled, int minLevel, int maxLevel,
                        PathStrategy strategy, String templateName, int priority, int maxRequests,
                        List<String> entries, boolean legacyFallback) {
            this(id, name, enabled, minLevel, maxLevel, strategy, templateName, priority, maxRequests,
                    entries, legacyFallback, "", "", "1.0", "", System.currentTimeMillis());
        }

        public DictionaryGroup(String id, String name, boolean enabled, int minLevel, int maxLevel,
                        PathStrategy strategy, String templateName, int priority, int maxRequests,
                        List<String> entries, boolean legacyFallback, String category, String tags,
                        String version, String description, long updatedAt) {
            this.id = blank(id) ? UUID.randomUUID().toString() : id;
            this.name = blank(name) ? "未命名字典组" : name.trim();
            this.enabled = enabled;
            int low = clamp(minLevel, MIN_LEVEL, MAX_LEVEL);
            int high = clamp(maxLevel, MIN_LEVEL, MAX_LEVEL);
            this.minLevel = Math.min(low, high);
            this.maxLevel = Math.max(low, high);
            this.strategy = strategy == null ? PathStrategy.CURRENT : strategy;
            this.templateName = safe(templateName).trim();
            this.category = safe(category).trim();
            this.tags = safe(tags).trim();
            this.version = blank(version) ? "1.0" : safe(version).trim();
            this.description = safe(description).trim();
            this.updatedAt = updatedAt <= 0 ? System.currentTimeMillis() : updatedAt;
            this.priority = priority;
            this.maxRequests = Math.max(1, maxRequests <= 0 ? DEFAULT_MAX_REQUESTS : maxRequests);
            this.entries = immutableEntries(entries);
            this.legacyFallback = legacyFallback;
        }

        public boolean matchesLevel(int level) {
            return enabled && level >= minLevel && level <= maxLevel && !entries.isEmpty();
        }

        public boolean matchesTemplate(Object requestGroup) {
            if (blank(templateName)) return true;
            return templateName.equals(BurpExtensionAccess.readStringField(requestGroup, "name"));
        }

        public String levelText() {
            return minLevel == maxLevel ? String.valueOf(minLevel) : minLevel + "-" + maxLevel;
        }

        public String summary() {
            return name + "[" + levelText() + ", " + strategy.label + ", "
                    + entries.size() + " 条" + (blank(templateName) ? "" : ", 模板=" + templateName)
                    + (blank(category) ? "" : ", 分类=" + category) + "]";
        }

        DictionaryGroup withEntries(List<String> nextEntries) {
            return new DictionaryGroup(id, name, enabled, minLevel, maxLevel, strategy, templateName,
                    priority, maxRequests, nextEntries, legacyFallback, category, tags, version, description,
                    System.currentTimeMillis());
        }
    }

    public synchronized List<DictionaryGroup> load(List<String> legacyEntries) {
        List<DictionaryGroup> configured = readConfiguredGroups();
        if (!configured.isEmpty()) return configured;

        // First-run behavior: materialize built-in preset dictionary groups so the UI shows
        // real layered groups instead of only the legacy fallback row. Existing user groups
        // are never overwritten because this branch only runs when no configured group exists.
        List<DictionaryGroup> presets = new ArrayList<DictionaryGroup>(
                PresetLayeredDictionaryGroups.create(legacyEntries));
        if (presets.isEmpty()) return Collections.emptyList();
        try {
            save(presets);
            List<DictionaryGroup> saved = readConfiguredGroups();
            return saved.isEmpty() ? Collections.unmodifiableList(presets) : saved;
        } catch (IOException ignored) {
            return Collections.unmodifiableList(presets);
        }
    }

    public synchronized List<DictionaryGroup> loadConfiguredOnly() {
        return readConfiguredGroups();
    }

    public synchronized void save(List<DictionaryGroup> groups) throws IOException {
        List<DictionaryGroup> cleaned = new ArrayList<DictionaryGroup>();
        if (groups != null) {
            for (DictionaryGroup group : groups) {
                if (group == null || group.legacyFallback) continue;
                if (cleaned.size() >= MAX_GROUPS) break;
                cleaned.add(group);
            }
        }
        Properties properties = new Properties();
        properties.setProperty("version", "1");
        properties.setProperty("count", String.valueOf(cleaned.size()));
        for (int i = 0; i < cleaned.size(); i++) {
            DictionaryGroup group = cleaned.get(i);
            String prefix = "group." + i + ".";
            properties.setProperty(prefix + "id", group.id);
            properties.setProperty(prefix + "name", group.name);
            properties.setProperty(prefix + "enabled", String.valueOf(group.enabled));
            properties.setProperty(prefix + "minLevel", String.valueOf(group.minLevel));
            properties.setProperty(prefix + "maxLevel", String.valueOf(group.maxLevel));
            properties.setProperty(prefix + "strategy", group.strategy.name());
            properties.setProperty(prefix + "templateName", group.templateName);
            properties.setProperty(prefix + "category", group.category);
            properties.setProperty(prefix + "tags", group.tags);
            properties.setProperty(prefix + "groupVersion", group.version);
            properties.setProperty(prefix + "description", group.description);
            properties.setProperty(prefix + "updatedAt", String.valueOf(group.updatedAt));
            properties.setProperty(prefix + "priority", String.valueOf(group.priority));
            properties.setProperty(prefix + "maxRequests", String.valueOf(group.maxRequests));
            properties.setProperty(prefix + "entries", joinEntries(group.entries));
        }
        File tmp = new File(FILE.getPath() + ".tmp");
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(tmp), StandardCharsets.UTF_8))) {
            properties.store(writer, "CGN layered dictionary groups");
        }
        if (!tmp.renameTo(FILE)) {
            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(FILE), StandardCharsets.UTF_8))) {
                properties.store(writer, "CGN layered dictionary groups");
            }
            // best effort cleanup; failure is not fatal.
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
        }
    }

    public synchronized void addOrUpdate(DictionaryGroup group) throws IOException {
        if (group == null) return;
        List<DictionaryGroup> groups = new ArrayList<DictionaryGroup>(loadConfiguredOnly());
        boolean updated = false;
        for (int i = 0; i < groups.size(); i++) {
            if (groups.get(i).id.equals(group.id)) {
                groups.set(i, group);
                updated = true;
                break;
            }
        }
        if (!updated) groups.add(group);
        Collections.sort(groups, (left, right) -> Integer.compare(left.priority, right.priority));
        save(groups);
    }

    public synchronized void delete(String id) throws IOException {
        if (blank(id)) return;
        List<DictionaryGroup> groups = new ArrayList<DictionaryGroup>(loadConfiguredOnly());
        groups.removeIf(group -> id.equals(group.id));
        save(groups);
    }

    public synchronized int importEntries(String id, File input) throws IOException {
        if (blank(id)) throw new IOException("Dictionary group id is required");
        if (input == null || !input.isFile()) throw new IOException("Dictionary file does not exist");
        if (input.length() > MAX_IMPORT_BYTES) {
            throw new IOException("Dictionary file is too large; max " + MAX_IMPORT_BYTES + " bytes");
        }
        List<DictionaryGroup> groups = new ArrayList<DictionaryGroup>(loadConfiguredOnly());
        for (int i = 0; i < groups.size(); i++) {
            DictionaryGroup group = groups.get(i);
            if (!id.equals(group.id)) continue;
            List<String> merged = new ArrayList<String>(group.entries);
            merged.addAll(readDictionaryFile(input));
            groups.set(i, group.withEntries(merged));
            save(groups);
            return groups.get(i).entries.size();
        }
        throw new IOException("Dictionary group not found: " + id);
    }

    public synchronized void exportEntries(String id, File output) throws IOException {
        if (blank(id)) throw new IOException("Dictionary group id is required");
        if (output == null) throw new IOException("Output file is required");
        for (DictionaryGroup group : loadConfiguredOnly()) {
            if (!id.equals(group.id)) continue;
            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(output), StandardCharsets.UTF_8))) {
                for (String entry : group.entries) {
                    writer.write(entry);
                    writer.newLine();
                }
            }
            return;
        }
        throw new IOException("Dictionary group not found: " + id);
    }

    public String fingerprint(List<DictionaryGroup> groups) {
        StringBuilder serialized = new StringBuilder();
        if (groups != null) {
            for (DictionaryGroup group : groups) {
                serialized.append(group.id).append('\u001f')
                        .append(group.name).append('\u001f')
                        .append(group.enabled).append('\u001f')
                        .append(group.minLevel).append('-').append(group.maxLevel).append('\u001f')
                        .append(group.strategy.name()).append('\u001f')
                        .append(group.templateName).append('\u001f')
                        .append(group.priority).append('\u001f')
                        .append(group.maxRequests).append('\u001f')
                        .append(group.entries).append('\u001e');
            }
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(serialized.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(64);
            for (byte b : digest) hex.append(String.format("%02x", b & 0xff));
            return hex.substring(0, 16);
        } catch (Exception ignored) {
            return Integer.toHexString(serialized.toString().hashCode());
        }
    }

    private List<DictionaryGroup> readConfiguredGroups() {
        if (!FILE.isFile()) return Collections.emptyList();
        Properties properties = new Properties();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(FILE), StandardCharsets.UTF_8))) {
            properties.load(reader);
        } catch (IOException e) {
            return Collections.emptyList();
        }
        int count = parseInt(properties.getProperty("count"), 0);
        List<DictionaryGroup> groups = new ArrayList<DictionaryGroup>();
        for (int i = 0; i < count && groups.size() < MAX_GROUPS; i++) {
            String prefix = "group." + i + ".";
            String id = properties.getProperty(prefix + "id", UUID.randomUUID().toString());
            String name = properties.getProperty(prefix + "name", "字典组 " + (i + 1));
            boolean enabled = Boolean.parseBoolean(properties.getProperty(prefix + "enabled", "true"));
            int min = parseInt(properties.getProperty(prefix + "minLevel"), 0);
            int max = parseInt(properties.getProperty(prefix + "maxLevel"), 4);
            PathStrategy strategy = PathStrategy.parse(properties.getProperty(prefix + "strategy"));
            String template = properties.getProperty(prefix + "templateName", "");
            String category = properties.getProperty(prefix + "category", "");
            String tags = properties.getProperty(prefix + "tags", "");
            String groupVersion = properties.getProperty(prefix + "groupVersion", "1.0");
            String description = properties.getProperty(prefix + "description", "");
            long updatedAt = parseLong(properties.getProperty(prefix + "updatedAt"), System.currentTimeMillis());
            int priority = parseInt(properties.getProperty(prefix + "priority"), i * 10);
            int maxRequests = parseInt(properties.getProperty(prefix + "maxRequests"), DEFAULT_MAX_REQUESTS);
            List<String> entries = parseEntries(properties.getProperty(prefix + "entries", ""));
            groups.add(new DictionaryGroup(id, name, enabled, min, max, strategy, template,
                    priority, maxRequests, entries, false, category, tags, groupVersion, description, updatedAt));
        }
        Collections.sort(groups, (left, right) -> Integer.compare(left.priority, right.priority));
        return Collections.unmodifiableList(groups);
    }

    private static List<String> readDictionaryFile(File input) throws IOException {
        List<String> entries = new ArrayList<String>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(input), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                entries.add(line);
                if (entries.size() >= MAX_ENTRIES_PER_GROUP) break;
            }
        }
        return entries;
    }

    public static List<String> sanitizeEntries(List<String> rawEntries) {
        List<String> values = new ArrayList<String>();
        if (rawEntries != null) {
            for (String raw : rawEntries) addEntry(values, raw);
        }
        return Collections.unmodifiableList(values);
    }

    private static List<String> immutableEntries(List<String> rawEntries) {
        return Collections.unmodifiableList(new ArrayList<String>(sanitizeEntries(rawEntries)));
    }

    private static List<String> parseEntries(String value) {
        List<String> entries = new ArrayList<String>();
        if (value != null) {
            for (String raw : value.split("\\n")) addEntry(entries, raw);
        }
        return Collections.unmodifiableList(entries);
    }

    private static void addEntry(List<String> entries, String raw) {
        if (entries.size() >= MAX_ENTRIES_PER_GROUP) return;
        String value = safe(raw).trim();
        if (value.length() == 0 || value.startsWith("#")) return;
        // Avoid path/header injection through imported dictionaries.
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\0') >= 0) return;
        if (!entries.contains(value)) entries.add(value);
    }

    private static String joinEntries(List<String> entries) {
        StringBuilder builder = new StringBuilder();
        if (entries != null) {
            for (String entry : entries) {
                if (builder.length() > 0) builder.append('\n');
                builder.append(entry);
            }
        }
        return builder.toString();
    }

    private static int parseInt(String value, int fallback) {
        try { return Integer.parseInt(safe(value).trim()); } catch (Exception ignored) { return fallback; }
    }

    private static long parseLong(String value, long fallback) {
        try { return Long.parseLong(safe(value).trim()); } catch (Exception ignored) { return fallback; }
    }

    private static int clamp(int value, int min, int max) { return Math.max(min, Math.min(max, value)); }
    private static boolean blank(String value) { return value == null || value.trim().isEmpty(); }
    private static String safe(String value) { return value == null ? "" : value; }
}
