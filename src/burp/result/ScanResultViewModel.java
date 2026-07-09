package burp.result;

import burp.*;
import burp.bootstrap.*;
import burp.config.*;
import burp.dictionary.*;
import burp.fingerprint.*;
import burp.js.*;
import burp.request.*;
import burp.result.*;
import burp.traffic.*;

import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

/**
 * EDT-confined result projection for the legacy BurpExtender table model.
 *
 * <p>The original plugin stores all results in {@code log}, rebuilds the filtered {@code log2}
 * list by scanning the whole log on every result, and then fires a whole-table event. This model
 * keeps host and status indexes, updates the displayed page incrementally, and only performs a
 * bounded page rebuild when a user changes a filter or page.</p>
 */
public final class ScanResultViewModel {
    public static final int DEFAULT_PAGE_SIZE = 500;
    public static final int MIN_PAGE_SIZE = 100;
    public static final int MAX_PAGE_SIZE = 1000;
    public static final int UI_REFRESH_INTERVAL_MS = 350;
    public static final int RECONCILE_INTERVAL_MS = 2500;

    private static final int[] PRIMARY_STATUSES = {200, 301, 302, 400, 401, 403, 404};

    private final BurpExtender extender;
    private final BurpViewModel owner;
    private final ConcurrentLinkedQueue<Object> pendingEntries = new ConcurrentLinkedQueue<Object>();
    private final AtomicBoolean refreshPending = new AtomicBoolean(false);

    /** All fields below are EDT-confined. */
    private final List<EntryMeta> ordered = new ArrayList<EntryMeta>();
    private final IdentityHashMap<Object, EntryMeta> metadataByIdentity = new IdentityHashMap<Object, EntryMeta>();
    private final Map<String, List<EntryMeta>> byHost = new HashMap<String, List<EntryMeta>>();
    private final Map<Integer, List<EntryMeta>> byStatus = new HashMap<Integer, List<EntryMeta>>();
    private final List<EntryMeta> otherStatus = new ArrayList<EntryMeta>();
    private final Map<String, StatusCounts> hostCounts = new HashMap<String, StatusCounts>();
    private final StatusCounts globalCounts = new StatusCounts();

    private Timer refreshTimer;
    private Timer reconcileTimer;
    private Timer filterDebounce;
    private boolean initialized;
    private long nextSequence;
    private int pageSize = DEFAULT_PAGE_SIZE;
    private int pageIndex;
    private int matchingEntries;
    private List<EntryMeta> displayed = Collections.emptyList();
    private JLabel pageLabel;
    private int fullIndexRebuilds;
    private int incrementalFlushes;

    public ScanResultViewModel(BurpExtender extender, BurpViewModel owner) {
        this.extender = extender;
        this.owner = owner;
    }

    /** Called exactly once after legacy controls exist; must run on the EDT. */
    public void bindOnEdt() {
        requireEdt();
        if (initialized) return;
        initialized = true;
        rebuildIndexesFromLegacyLog();
        wireLegacyFilters();
        startReconciler();
        rebuildProjection(true);
    }

    public void onLogEntryAdded(Object entry) {
        if (entry == null) return;
        pendingEntries.offer(entry);
        scheduleFlush(false, false);
    }

    /** Replaces legacy scan_uri_filter() after UI interactions. */
    public void onLegacyFilterRequested() {
        scheduleFlush(true, true);
    }

    /** Replaces legacy fireScanTableChanged() without generating a full table invalidation. */
    public void onLegacyTableRefreshRequested() {
        scheduleFlush(false, false);
    }

    public void installPerformanceControls(JPanel content) {
        requireEdt();
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createTitledBorder("结果展示性能"));
        panel.add(new JLabel("每页最多："));
        final JSpinner rows = new JSpinner(new SpinnerNumberModel(pageSize,
                MIN_PAGE_SIZE, MAX_PAGE_SIZE, 100));
        rows.addChangeListener(event -> {
            pageSize = ((Number) rows.getValue()).intValue();
            pageIndex = 0;
            scheduleFlush(true, true);
        });
        panel.add(rows);

        JButton previous = new JButton("上一页");
        previous.addActionListener(event -> {
            if (pageIndex > 0) {
                pageIndex--;
                scheduleFlush(true, true);
            }
        });
        panel.add(previous);

        JButton next = new JButton("下一页");
        next.addActionListener(event -> {
            int pages = pageCountInstance(matchingEntries);
            if (pageIndex + 1 < pages) {
                pageIndex++;
                scheduleFlush(true, true);
            }
        });
        panel.add(next);

        JButton rebuild = new JButton("重建结果索引");
        rebuild.setToolTipText("仅在旧版外部逻辑直接修改日志时使用；正常扫描无需点击。");
        rebuild.addActionListener(event -> {
            rebuildIndexesFromLegacyLog();
            pageIndex = 0;
            rebuildProjection(true);
        });
        panel.add(rebuild);

        pageLabel = new JLabel();
        panel.add(pageLabel);
        content.add(panel);
        updateLabels();
    }

    public void shutdown() {
        owner.onEdt(new Runnable() {
            public void run() {
                if (refreshTimer != null) refreshTimer.stop();
                if (reconcileTimer != null) reconcileTimer.stop();
                if (filterDebounce != null) filterDebounce.stop();
            }
        });
    }

    public ResultUiMetrics diagnostics() {
        if (!SwingUtilities.isEventDispatchThread()) {
            // Diagnostics are deliberately approximate when called by a test/worker thread.
            return new ResultUiMetrics(ordered.size(), displayed.size(), matchingEntries,
                    fullIndexRebuilds, incrementalFlushes, pageSize, pageIndex);
        }
        return new ResultUiMetrics(ordered.size(), displayed.size(), matchingEntries,
                fullIndexRebuilds, incrementalFlushes, pageSize, pageIndex);
    }

    private void wireLegacyFilters() {
        for (String name : statusControlNames()) {
            Object value = field(name);
            if (value instanceof AbstractButton) {
                ((AbstractButton) value).addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent event) { scheduleFilterRebuild(); }
                });
            }
        }
        Object table = field("jp_host_table");
        if (table instanceof JTable) {
            ((JTable) table).getSelectionModel().addListSelectionListener(new ListSelectionListener() {
                public void valueChanged(ListSelectionEvent event) {
                    if (!event.getValueIsAdjusting()) scheduleFilterRebuild();
                }
            });
        }
    }

    private void scheduleFilterRebuild() {
        if (!SwingUtilities.isEventDispatchThread()) {
            owner.onEdt(new Runnable() { public void run() { scheduleFilterRebuild(); } });
            return;
        }
        if (filterDebounce == null) {
            filterDebounce = new Timer(80, new ActionListener() {
                public void actionPerformed(ActionEvent event) {
                    pageIndex = 0;
                    scheduleFlush(true, true);
                }
            });
            filterDebounce.setRepeats(false);
        }
        filterDebounce.restart();
    }

    private void startReconciler() {
        if (reconcileTimer != null) return;
        reconcileTimer = new Timer(RECONCILE_INTERVAL_MS, new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                // External/legacy writers are reconciled by tail identity. This is not on each result.
                if (reconcileLegacyTail()) rebuildProjection(false);
            }
        });
        reconcileTimer.setRepeats(true);
        reconcileTimer.start();
    }

    private void scheduleFlush(final boolean immediate, final boolean filterChanged) {
        if (!refreshPending.compareAndSet(false, true)) return;
        owner.onEdt(new Runnable() {
            public void run() {
                ensureRefreshTimer();
                if (immediate) {
                    refreshTimer.stop();
                    refreshPending.set(false);
                    flush(filterChanged);
                } else {
                    refreshTimer.restart();
                }
            }
        });
    }

    private void ensureRefreshTimer() {
        requireEdt();
        if (refreshTimer != null) return;
        refreshTimer = new Timer(UI_REFRESH_INTERVAL_MS, new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                refreshPending.set(false);
                flush(false);
            }
        });
        refreshTimer.setRepeats(false);
    }

    private void flush(boolean filterChanged) {
        requireEdt();
        boolean changed = drainPendingEntries();
        // A filter event may originate from legacy UI code that wrote the backing log directly.
        // Reconcile by tail identity once here; ordinary result append events use the queue above.
        if (filterChanged) changed |= reconcileLegacyTail();
        changed |= trimToLegacyCapacity();
        if (filterChanged || changed) rebuildProjection(filterChanged);
        else updateLabels();

        // Do not strand an entry that arrived while this EDT flush was running.
        if (!pendingEntries.isEmpty()) scheduleFlush(false, false);
    }

    private boolean drainPendingEntries() {
        boolean changed = false;
        Object entry;
        while ((entry = pendingEntries.poll()) != null) {
            changed |= indexEntry(entry);
        }
        return changed;
    }

    private boolean trimToLegacyCapacity() {
        int size = legacyLogSize();
        boolean changed = false;
        while (ordered.size() > size && !ordered.isEmpty()) {
            removeEntry(ordered.get(0));
            changed = true;
        }
        return changed;
    }

    /**
     * Reconciles only the legacy-log tail when possible. A full rebuild is used only if the
     * previously indexed tail vanished (for example a user cleared all results).
     */
    private boolean reconcileLegacyTail() {
        requireEdt();
        List<Object> snapshot = snapshotLegacyLog();
        if (snapshot.isEmpty()) {
            if (ordered.isEmpty()) return false;
            clearIndexes();
            return true;
        }
        if (ordered.isEmpty()) {
            for (Object entry : snapshot) indexEntry(entry);
            return true;
        }

        Object tail = ordered.get(ordered.size() - 1).entry;
        int tailAt = identityIndexOf(snapshot, tail);
        if (tailAt < 0) {
            rebuildIndexes(snapshot);
            return true;
        }

        IdentityHashMap<Object, Boolean> current = new IdentityHashMap<Object, Boolean>();
        for (Object entry : snapshot) current.put(entry, Boolean.TRUE);
        boolean changed = false;
        while (!ordered.isEmpty() && !current.containsKey(ordered.get(0).entry)) {
            removeEntry(ordered.get(0));
            changed = true;
        }
        for (int i = tailAt + 1; i < snapshot.size(); i++) changed |= indexEntry(snapshot.get(i));
        return changed;
    }

    private void rebuildIndexesFromLegacyLog() {
        requireEdt();
        rebuildIndexes(snapshotLegacyLog());
    }

    private void rebuildIndexes(List<Object> snapshot) {
        clearIndexes();
        for (Object entry : snapshot) indexEntry(entry);
        fullIndexRebuilds++;
    }

    private void clearIndexes() {
        ordered.clear();
        metadataByIdentity.clear();
        byHost.clear();
        byStatus.clear();
        otherStatus.clear();
        hostCounts.clear();
        globalCounts.clear();
        nextSequence = 0L;
    }

    private boolean indexEntry(Object entry) {
        requireEdt();
        if (entry == null || metadataByIdentity.containsKey(entry)) return false;
        String url = BurpExtensionAccess.readStringField(entry, "url");
        int status = BurpExtensionAccess.readIntField(entry, "response_code", 0);
        EntryMeta meta = new EntryMeta(entry, normalizeHost(url), status, nextSequence++);
        ordered.add(meta);
        metadataByIdentity.put(entry, meta);
        listFor(byHost, meta.host).add(meta);
        if (isPrimaryStatus(status)) listFor(byStatus, Integer.valueOf(status)).add(meta);
        else otherStatus.add(meta);
        globalCounts.increment(status);
        countsForHost(meta.host).increment(status);
        return true;
    }

    private void removeEntry(EntryMeta meta) {
        if (meta == null) return;
        ordered.remove(meta);
        metadataByIdentity.remove(meta.entry);
        removeFrom(byHost.get(meta.host), meta);
        if (isPrimaryStatus(meta.status)) removeFrom(byStatus.get(Integer.valueOf(meta.status)), meta);
        else otherStatus.remove(meta);
        globalCounts.decrement(meta.status);
        StatusCounts host = hostCounts.get(meta.host);
        if (host != null) {
            host.decrement(meta.status);
            if (host.total == 0) hostCounts.remove(meta.host);
        }
    }

    private void rebuildProjection(boolean forceTableDataChange) {
        requireEdt();
        FilterState filter = captureFilterState();
        List<EntryMeta> matches = matchingEntries(filter);
        matchingEntries = matches.size();
        int pages = pageCountInstance(matchingEntries);
        if (pages == 0) pageIndex = 0;
        else pageIndex = Math.min(Math.max(0, pageIndex), pages - 1);
        int start = pageIndex * pageSize;
        int end = Math.min(start + pageSize, matchingEntries);
        List<EntryMeta> next = start >= end
                ? Collections.<EntryMeta>emptyList()
                : new ArrayList<EntryMeta>(matches.subList(start, end));
        applyProjection(next, forceTableDataChange);
        updateLabels(filter);
        incrementalFlushes++;
    }

    private List<EntryMeta> matchingEntries(FilterState filter) {
        if (filter.host.length() > 0) {
            List<EntryMeta> hostEntries = byHost.get(filter.host);
            if (hostEntries == null || hostEntries.isEmpty()) return Collections.emptyList();
            List<EntryMeta> output = new ArrayList<EntryMeta>();
            for (EntryMeta meta : hostEntries) if (filter.accepts(meta.status)) output.add(meta);
            return output;
        }

        // Host is not selected: merge status buckets rather than walking the master log again.
        List<EntryMeta> output = new ArrayList<EntryMeta>();
        for (int code : PRIMARY_STATUSES) {
            if (!filter.accepts(code)) continue;
            List<EntryMeta> bucket = byStatus.get(Integer.valueOf(code));
            if (bucket != null) output.addAll(bucket);
        }
        if (filter.other) output.addAll(otherStatus);
        Collections.sort(output, Comparator.comparingLong(meta -> meta.sequence));
        return output;
    }

    @SuppressWarnings("unchecked")
    private void applyProjection(List<EntryMeta> next, boolean forceTableDataChange) {
        List<Object> legacyVisible = legacyVisibleLog();
        if (legacyVisible == null) return;
        List<EntryMeta> before = displayed;
        synchronized (legacyVisible) {
            legacyVisible.clear();
            for (EntryMeta meta : next) legacyVisible.add(meta.entry);
        }
        displayed = Collections.unmodifiableList(new ArrayList<EntryMeta>(next));

        if (forceTableDataChange || before.isEmpty() && !next.isEmpty() && legacyVisible.size() != next.size()) {
            extender.fireTableDataChanged();
            return;
        }
        emitTableDelta(before, next);
    }

    private void emitTableDelta(List<EntryMeta> before, List<EntryMeta> next) {
        int oldSize = before.size();
        int newSize = next.size();
        if (oldSize == 0 && newSize == 0) return;
        int prefix = 0;
        int limit = Math.min(oldSize, newSize);
        while (prefix < limit && before.get(prefix).entry == next.get(prefix).entry) prefix++;

        if (prefix == oldSize && newSize > oldSize) {
            extender.fireTableRowsInserted(oldSize, newSize - 1);
            return;
        }
        if (prefix == newSize && oldSize > newSize) {
            extender.fireTableRowsDeleted(newSize, oldSize - 1);
            return;
        }
        if (oldSize == newSize) {
            extender.fireTableRowsUpdated(0, Math.max(0, newSize - 1));
            return;
        }
        // Bounded fallback: only the current page (<= 1000), never the entire legacy log.
        extender.fireTableDataChanged();
    }

    private void updateLabels() { updateLabels(captureFilterState()); }

    private void updateLabels(FilterState filter) {
        requireEdt();
        int pages = pageCountInstance(matchingEntries);
        if (pageLabel != null) {
            pageLabel.setText("当前页 " + (pages == 0 ? 0 : pageIndex + 1) + "/" + pages
                    + "，匹配 " + matchingEntries + " 条，显示 " + displayed.size() + " 条");
        }
        Object summary = field("scan_summary_lb");
        if (!(summary instanceof JLabel)) return;
        StatusCounts counts = filter.host.length() == 0 ? globalCounts : hostCounts.get(filter.host);
        if (counts == null) counts = StatusCounts.EMPTY;
        int budget = BurpExtensionAccess.readIntField(extender, "globalScanRequestCount", 0);
        ((JLabel) summary).setText("结果视图筛选（不影响扫描范围） | 扫描请求=" + budget
                + " | 索引结果=" + counts.total
                + " | Host=" + (filter.host.length() == 0 ? "全部" : filter.host)
                + " | 200=" + counts.get(200) + " 301=" + counts.get(301)
                + " 302=" + counts.get(302) + " 400=" + counts.get(400)
                + " 401=" + counts.get(401) + " 403=" + counts.get(403)
                + " 404=" + counts.get(404) + " 其他=" + counts.other);
    }

    private FilterState captureFilterState() {
        requireEdt();
        String host = normalizeHost(String.valueOf(field("Hosts") == null ? "" : field("Hosts")));
        return new FilterState(host,
                selected("jp_host_uri_scan_3_jb"),
                selected("jp_host_uri_scan_3_jb2"),
                selected("jp_host_uri_scan_3_jb3"),
                selected("jp_host_uri_scan_3_jb4"),
                selected("jp_host_uri_scan_3_jb5"),
                selected("jp_host_uri_scan_3_jb6"),
                selected("jp_host_uri_scan_3_jb7"),
                selected("jp_host_uri_scan_3_jb8"));
    }

    private List<Object> snapshotLegacyLog() {
        List<Object> raw = legacyLog();
        if (raw == null) return Collections.emptyList();
        synchronized (raw) { return new ArrayList<Object>(raw); }
    }

    private int legacyLogSize() {
        List<Object> raw = legacyLog();
        if (raw == null) return 0;
        synchronized (raw) { return raw.size(); }
    }

    @SuppressWarnings("unchecked")
    private List<Object> legacyLog() {
        Object value = field("log");
        return value instanceof List<?> ? (List<Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    private List<Object> legacyVisibleLog() {
        Object value = field("log2");
        return value instanceof List<?> ? (List<Object>) value : null;
    }

    private Object field(String name) {
        try { return BurpExtensionAccess.readField(extender, name); }
        catch (Exception ignored) { return null; }
    }

    private boolean selected(String name) {
        Object value = field(name);
        return value instanceof AbstractButton && ((AbstractButton) value).isSelected();
    }

    private static String normalizeHost(String urlOrHost) {
        if (urlOrHost == null) return "";
        String value = urlOrHost.trim();
        if (value.length() == 0) return "";
        try { return new URL(value).getHost().trim().toLowerCase(Locale.ROOT); }
        catch (Exception ignored) { return value.toLowerCase(Locale.ROOT); }
    }

    private static boolean isPrimaryStatus(int status) {
        for (int code : PRIMARY_STATUSES) if (code == status) return true;
        return false;
    }

        private int pageCountInstance(int entries) {
        return entries <= 0 ? 0 : ((entries - 1) / Math.max(1, pageSize)) + 1;
    }

    private static int identityIndexOf(List<Object> entries, Object target) {
        for (int i = entries.size() - 1; i >= 0; i--) if (entries.get(i) == target) return i;
        return -1;
    }

    private static <K> List<EntryMeta> listFor(Map<K, List<EntryMeta>> map, K key) {
        List<EntryMeta> existing = map.get(key);
        if (existing != null) return existing;
        List<EntryMeta> created = new ArrayList<EntryMeta>();
        map.put(key, created);
        return created;
    }

    private static void removeFrom(List<EntryMeta> list, EntryMeta meta) {
        if (list != null) list.remove(meta);
    }

    private StatusCounts countsForHost(String host) {
        StatusCounts existing = hostCounts.get(host);
        if (existing != null) return existing;
        StatusCounts created = new StatusCounts();
        hostCounts.put(host, created);
        return created;
    }

    private static String[] statusControlNames() {
        return new String[] { "jp_host_uri_scan_3_jb", "jp_host_uri_scan_3_jb2",
                "jp_host_uri_scan_3_jb3", "jp_host_uri_scan_3_jb4",
                "jp_host_uri_scan_3_jb5", "jp_host_uri_scan_3_jb6",
                "jp_host_uri_scan_3_jb7", "jp_host_uri_scan_3_jb8" };
    }

    private static void requireEdt() {
        if (!SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException("ScanResultViewModel must execute on the EDT");
        }
    }

    public static final class ResultUiMetrics {
        public final int indexedEntries;
        public final int displayedEntries;
        public final int matchedEntries;
        public final int fullIndexRebuilds;
        public final int incrementalFlushes;
        public final int pageSize;
        public final int pageIndex;
        public ResultUiMetrics(int indexedEntries, int displayedEntries, int matchedEntries,
                        int fullIndexRebuilds, int incrementalFlushes, int pageSize, int pageIndex) {
            this.indexedEntries = indexedEntries;
            this.displayedEntries = displayedEntries;
            this.matchedEntries = matchedEntries;
            this.fullIndexRebuilds = fullIndexRebuilds;
            this.incrementalFlushes = incrementalFlushes;
            this.pageSize = pageSize;
            this.pageIndex = pageIndex;
        }
    }

    private static final class EntryMeta {
        final Object entry;
        final String host;
        final int status;
        final long sequence;
        EntryMeta(Object entry, String host, int status, long sequence) {
            this.entry = entry; this.host = host; this.status = status; this.sequence = sequence;
        }
    }

    private static final class FilterState {
        final String host;
        final boolean s200, s301, s302, s400, s401, s403, s404, other;
        FilterState(String host, boolean s200, boolean s301, boolean s302, boolean s400,
                    boolean s401, boolean s403, boolean s404, boolean other) {
            this.host = host;
            this.s200 = s200; this.s301 = s301; this.s302 = s302; this.s400 = s400;
            this.s401 = s401; this.s403 = s403; this.s404 = s404; this.other = other;
        }
        boolean accepts(int status) {
            switch (status) {
                case 200: return s200;
                case 301: return s301;
                case 302: return s302;
                case 400: return s400;
                case 401: return s401;
                case 403: return s403;
                case 404: return s404;
                default: return other;
            }
        }
    }

    private static final class StatusCounts {
        static final StatusCounts EMPTY = new StatusCounts();
        int total;
        int c200, c301, c302, c400, c401, c403, c404, other;
        void increment(int status) { total++; add(status, 1); }
        void decrement(int status) { total = Math.max(0, total - 1); add(status, -1); }
        void clear() { total = c200 = c301 = c302 = c400 = c401 = c403 = c404 = other = 0; }
        int get(int status) {
            switch (status) {
                case 200: return c200; case 301: return c301; case 302: return c302;
                case 400: return c400; case 401: return c401; case 403: return c403;
                case 404: return c404; default: return other;
            }
        }
        private void add(int status, int delta) {
            switch (status) {
                case 200: c200 = Math.max(0, c200 + delta); break;
                case 301: c301 = Math.max(0, c301 + delta); break;
                case 302: c302 = Math.max(0, c302 + delta); break;
                case 400: c400 = Math.max(0, c400 + delta); break;
                case 401: c401 = Math.max(0, c401 + delta); break;
                case 403: c403 = Math.max(0, c403 + delta); break;
                case 404: c404 = Math.max(0, c404 + delta); break;
                default: other = Math.max(0, other + delta); break;
            }
        }
    }
}
