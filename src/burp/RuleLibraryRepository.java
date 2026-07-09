package burp;

import burp.dictionary.LayeredDictionaryStore;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
/**
 * Repository boundary over the original RuleLibraryStore. New code calls this interface rather
 * than reaching into BurpExtender fields; the existing V5.6.1 UI remains binary-compatible.
 */
public final class RuleLibraryRepository {
    private final BurpExtender extender;
    private final LayeredDictionaryStore layeredDictionaryStore = new LayeredDictionaryStore();
    public RuleLibraryRepository(BurpExtender extender) { this.extender = extender; }

    public RuleSnapshot snapshot() throws Exception {
        // Request templates still use V5.6.1's private RequestGroup presentation model, so the
        // immutable scan snapshot is intentionally sourced through that compatibility seam.
        List<String> paths = pathEntries();
        List<Object> groups = requestGroups();
        List<LayeredDictionaryStore.DictionaryGroup> dictionaryGroups = layeredDictionaryStore.load(paths);
        return new RuleSnapshot(paths, groups, dictionaryGroups,
                fingerprint(groups, paths) + ":" + layeredDictionaryStore.fingerprint(dictionaryGroups));
    }

    public List<RuleLibraryStore.RuleLibrary> snapshotAll() throws IOException {
        return store().snapshotAll();
    }

    RuleLibraryStore.RuleLibrary find(String libraryId) throws IOException {
        return store().findSnapshot(libraryId);
    }

    RuleLibraryStore.RuleLibrary create(String group, String name, String description,
                                        RuleLibraryStore.RuleType type, boolean enabled)
            throws IOException {
        return store().createLibrary(group, name, description, type, enabled);
    }

    public void update(String libraryId, String group, String name, String description, boolean enabled)
            throws IOException {
        store().updateLibrary(libraryId, group, name, description, enabled);
    }

    public void delete(String libraryId) throws IOException { store().deleteLibrary(libraryId); }

    RuleLibraryStore.RuleLibrary copyToCustom(String sourceId, String group, String name)
            throws IOException {
        return store().copyToCustom(sourceId, group, name);
    }

    RuleLibraryStore.RuleDefinition addRule(String libraryId, RuleLibraryStore.RuleDefinition rule)
            throws IOException {
        return store().addRule(libraryId, rule);
    }

    public void updateRule(String libraryId, String ruleId, RuleLibraryStore.RuleDefinition rule)
            throws IOException {
        store().updateRule(libraryId, ruleId, rule);
    }

    public void deleteRule(String libraryId, String ruleId) throws IOException {
        store().deleteRule(libraryId, ruleId);
    }

    public void setRuleEnabled(String libraryId, String ruleId, boolean enabled) throws IOException {
        store().setRuleEnabled(libraryId, ruleId, enabled);
    }

    public int importDictionary(String libraryId, File input) throws IOException {
        return store().importDictionary(libraryId, input);
    }

    public void exportDictionary(String libraryId, File output) throws IOException {
        store().exportDictionary(libraryId, output);
    }

    public void exportLibrary(String libraryId, File output) throws IOException {
        store().exportLibrary(libraryId, output);
    }

    RuleLibraryStore.RuleLibrary importLibrary(File input) throws IOException {
        return store().importLibrary(input);
    }

    public List<LayeredDictionaryStore.DictionaryGroup> dictionaryGroups() {
        return layeredDictionaryStore.loadConfiguredOnly();
    }

    public List<LayeredDictionaryStore.DictionaryGroup> effectiveDictionaryGroups() {
        try {
            return layeredDictionaryStore.load(pathEntries());
        } catch (Exception e) {
            return layeredDictionaryStore.load(Collections.<String>emptyList());
        }
    }

    public void saveDictionaryGroups(List<LayeredDictionaryStore.DictionaryGroup> groups) throws IOException {
        layeredDictionaryStore.save(groups);
    }

    public void addOrUpdateDictionaryGroup(LayeredDictionaryStore.DictionaryGroup group) throws IOException {
        layeredDictionaryStore.addOrUpdate(group);
    }

    public void deleteDictionaryGroup(String id) throws IOException {
        layeredDictionaryStore.delete(id);
    }

    public int importDictionaryGroupEntries(String id, File input) throws IOException {
        return layeredDictionaryStore.importEntries(id, input);
    }

    public void exportDictionaryGroupEntries(String id, File output) throws IOException {
        layeredDictionaryStore.exportEntries(id, output);
    }

    private RuleLibraryStore store() throws IOException {
        try {
            Object candidate = BurpExtensionAccess.readField(extender, "ruleLibraryStore");
            if (candidate instanceof RuleLibraryStore) return (RuleLibraryStore) candidate;
        } catch (Exception ignored) {
            // Unified IOException lets callers surface a normal repository failure, not reflection.
        }
        throw new IOException("CGN RuleLibraryStore is unavailable; extension initialization is incomplete");
    }

    @SuppressWarnings("unchecked")
    private List<String> pathEntries() throws Exception {
        Object result = BurpExtensionAccess.invokePrivate(extender, "getPathDictionaryEntries",
                new Class<?>[0], new Object[0]);
        if (!(result instanceof List<?>)) return Collections.emptyList();
        List<String> values = new ArrayList<String>();
        for (Object item : (List<Object>) result) if (item != null) values.add(String.valueOf(item));
        return values;
    }

    @SuppressWarnings("unchecked")
    private List<Object> requestGroups() throws Exception {
        Object result = BurpExtensionAccess.invokePrivate(extender, "snapshotRequestGroups",
                new Class<?>[0], new Object[0]);
        if (!(result instanceof List<?>)) return Collections.emptyList();
        return new ArrayList<Object>((List<Object>) result);
    }

    private static String fingerprint(List<Object> groups, List<String> paths) {
        StringBuilder serialized = new StringBuilder();
        for (Object group : groups) {
            serialized.append(BurpExtensionAccess.readStringField(group, "name")).append('\u001f')
                    .append(BurpExtensionAccess.readStringField(group, "method")).append('\u001f')
                    .append(BurpExtensionAccess.readStringField(group, "path")).append('\u001f')
                    .append(BurpExtensionAccess.readStringField(group, "body")).append('\u001f')
                    .append(BurpExtensionAccess.readStringField(group, "ruleMatch")).append('\u001f')
                    .append(BurpExtensionAccess.readStringField(group, "ruleDeny")).append('\u001e');
        }
        for (String path : paths) serialized.append(path).append('\n');
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

    public static final class RuleSnapshot {
        private final List<String> paths;
        private final List<Object> groups;
        private final List<LayeredDictionaryStore.DictionaryGroup> dictionaryGroups;
        private final String version;
        public RuleSnapshot(List<String> paths, List<Object> groups,
                     List<LayeredDictionaryStore.DictionaryGroup> dictionaryGroups, String version) {
            this.paths = Collections.unmodifiableList(new ArrayList<String>(paths));
            this.groups = Collections.unmodifiableList(new ArrayList<Object>(groups));
            this.dictionaryGroups = Collections.unmodifiableList(new ArrayList<LayeredDictionaryStore.DictionaryGroup>(dictionaryGroups));
            this.version = version;
        }
        public List<String> pathEntries() { return paths; }
        List<Object> requestGroups() { return groups; }
        public List<LayeredDictionaryStore.DictionaryGroup> dictionaryGroups() { return dictionaryGroups; }
        public String version() { return version; }
    }
}
