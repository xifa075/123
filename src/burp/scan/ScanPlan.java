package burp.scan;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.config.ScanConfig;
import burp.config.UiScanSnapshot;
import burp.dictionary.LayeredDictionaryStore;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Immutable execution plan created from one accepted Burp seed message. */
public final class ScanPlan {
    public final IHttpRequestResponse seed;
    public final IHttpService service;
    public final IRequestInfo baseRequestInfo;
    public final URL baseUrl;
    public final String normalizedHost;
    public final ScanSource source;
    public final List<String> dictionary;
    public final List<LayeredDictionaryStore.DictionaryGroup> dictionaryGroups;
    public final List<Object> requestGroups;
    public final String denyTokens;
    public final int intervalMillis;
    public final String templateVersion;
    public final ScanConfig settings;
    /** EDT-built immutable UI snapshot used to construct every request in this task. */
    public final UiScanSnapshot uiSnapshot;

    public ScanPlan(IHttpRequestResponse seed, IHttpService service, IRequestInfo baseRequestInfo,
                    URL baseUrl, String normalizedHost, ScanSource source, List<String> dictionary,
                    List<LayeredDictionaryStore.DictionaryGroup> dictionaryGroups,
                    List<Object> requestGroups, String denyTokens, int intervalMillis,
                    String templateVersion, ScanConfig settings, UiScanSnapshot uiSnapshot) {
        this.seed = seed;
        this.service = service;
        this.baseRequestInfo = baseRequestInfo;
        this.baseUrl = baseUrl;
        this.normalizedHost = normalizedHost;
        this.source = source;
        this.dictionary = Collections.unmodifiableList(new ArrayList<String>(dictionary));
        this.dictionaryGroups = Collections.unmodifiableList(new ArrayList<LayeredDictionaryStore.DictionaryGroup>(
                dictionaryGroups == null ? Collections.<LayeredDictionaryStore.DictionaryGroup>emptyList() : dictionaryGroups));
        this.requestGroups = Collections.unmodifiableList(new ArrayList<Object>(requestGroups));
        this.denyTokens = denyTokens == null ? "" : denyTokens;
        this.intervalMillis = Math.max(50, intervalMillis);
        this.templateVersion = templateVersion;
        this.settings = settings;
        this.uiSnapshot = uiSnapshot == null ? UiScanSnapshot.disabled() : uiSnapshot;
    }
}
