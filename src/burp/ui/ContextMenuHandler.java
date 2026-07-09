package burp.ui;

import burp.IHttpRequestResponse;
import burp.ScanOrchestrator;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.swing.JMenuItem;

/** Burp context-menu adapter kept out of the scheduler/reliability core. */
public final class ContextMenuHandler implements InvocationHandler {
    private final ScanOrchestrator orchestrator;

    public ContextMenuHandler(ScanOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if ("toString".equals(method.getName())) {
            return "CGN Reliability Context Menu";
        }
        if (!"createMenuItems".equals(method.getName())) {
            return null;
        }
        final List<IHttpRequestResponse> selected = selectedMessages(args == null || args.length == 0 ? null : args[0]);
        List<JMenuItem> items = new ArrayList<JMenuItem>();
        JMenuItem request = new JMenuItem("CGN: 扫描选中请求（可靠队列）");
        request.setEnabled(!selected.isEmpty());
        request.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                for (IHttpRequestResponse message : selected) {
                    orchestrator.enqueueManual(message);
                }
            }
        });
        items.add(request);

        JMenuItem host = new JMenuItem("CGN: 扫描当前 Host（可靠队列）");
        host.setEnabled(!selected.isEmpty());
        host.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Set<String> seen = new LinkedHashSet<String>();
                for (IHttpRequestResponse message : selected) {
                    String key = orchestrator.normalizedHost(message);
                    if (seen.add(key)) {
                        orchestrator.enqueueManual(message);
                    }
                }
            }
        });
        items.add(host);

        JMenuItem retry = new JMenuItem("CGN: 重新排队失败任务");
        retry.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                orchestrator.retryFailed();
            }
        });
        items.add(retry);
        return items;
    }

    private List<IHttpRequestResponse> selectedMessages(Object invocation) {
        if (invocation == null) {
            return Collections.emptyList();
        }
        try {
            Method method = invocation.getClass().getMethod("getSelectedMessages");
            Object result = method.invoke(invocation);
            if (result instanceof IHttpRequestResponse[]) {
                return Arrays.asList((IHttpRequestResponse[]) result);
            }
            if (result instanceof Object[]) {
                List<IHttpRequestResponse> messages = new ArrayList<IHttpRequestResponse>();
                for (Object item : (Object[]) result) {
                    if (item instanceof IHttpRequestResponse) {
                        messages.add((IHttpRequestResponse) item);
                    }
                }
                return messages;
            }
        } catch (Exception ignored) {
            // Context menu should still expose retry even if selection is unavailable.
        }
        return Collections.emptyList();
    }
}
