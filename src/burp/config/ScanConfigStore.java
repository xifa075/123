package burp.config;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Properties;
/** UTF-8, atomic persistence for immutable scan configuration snapshots. */
public final class ScanConfigStore {
    private static final String FILE_NAME = "cgn_reliability.properties";
    private ScanConfigStore() { }

    public static ScanConfig load() {
        ScanConfig defaults = ScanConfig.defaults();
        Path path = configPath();
        if (!Files.isRegularFile(path)) {
            save(defaults);
            return defaults;
        }
        Properties properties = new Properties();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
            return new ScanConfig(
                    bool(properties, "source.target", defaults.targetEnabled),
                    bool(properties, "source.proxy", defaults.proxyEnabled),
                    bool(properties, "source.scanner", defaults.scannerEnabled),
                    bool(properties, "source.intruder", defaults.intruderEnabled),
                    bool(properties, "source.repeater", defaults.repeaterEnabled),
                    bool(properties, "scope.required", defaults.scopeRequired),
                    bool(properties, "template.unsafe.methods.allowed", defaults.unsafeTemplateMethodsAllowed),
                    integer(properties, "retry.max", defaults.maxRetries),
                    integer(properties, "retry.initial.ms", defaults.retryInitialMillis),
                    integer(properties, "queue.pending.limit", defaults.pendingLimit));
        } catch (Exception ignored) {
            return defaults;
        }
    }

    public static void save(ScanConfig settings) {
        if (settings == null) return;
        Path path = configPath();
        Properties properties = new Properties();
        properties.setProperty("source.target", Boolean.toString(settings.targetEnabled));
        properties.setProperty("source.proxy", Boolean.toString(settings.proxyEnabled));
        properties.setProperty("source.scanner", Boolean.toString(settings.scannerEnabled));
        properties.setProperty("source.intruder", Boolean.toString(settings.intruderEnabled));
        properties.setProperty("source.repeater", Boolean.toString(settings.repeaterEnabled));
        properties.setProperty("scope.required", Boolean.toString(settings.scopeRequired));
        properties.setProperty("template.unsafe.methods.allowed", Boolean.toString(settings.unsafeTemplateMethodsAllowed));
        properties.setProperty("retry.max", Integer.toString(settings.maxRetries));
        properties.setProperty("retry.initial.ms", Integer.toString(settings.retryInitialMillis));
        properties.setProperty("queue.pending.limit", Integer.toString(settings.pendingLimit));
        properties.setProperty("version", "4");
        try {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            Path temporary = path.resolveSibling(path.getFileName().toString() + ".tmp");
            try (BufferedWriter writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                properties.store(writer, "CGN scan configuration");
            }
            try {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ignored) {
            // Runtime behavior must not fail because a local preference cannot be persisted.
        }
    }

    private static Path configPath() {
        return Path.of(System.getProperty("user.dir", "."), FILE_NAME);
    }

    private static boolean bool(Properties properties, String key, boolean fallback) {
        String value = properties.getProperty(key);
        return value == null ? fallback : Boolean.parseBoolean(value.trim());
    }

    private static int integer(Properties properties, String key, int fallback) {
        try { return Integer.parseInt(properties.getProperty(key, Integer.toString(fallback)).trim()); }
        catch (RuntimeException ignored) { return fallback; }
    }
}
