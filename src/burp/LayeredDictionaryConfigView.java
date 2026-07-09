package burp;

import burp.*;
import burp.bootstrap.*;
import burp.config.*;
import burp.dictionary.*;
import burp.fingerprint.*;
import burp.js.*;
import burp.request.*;
import burp.result.*;
import burp.traffic.*;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

/** Configuration-center page that turns the old flat path dictionary into depth-aware groups. */
public final class LayeredDictionaryConfigView {
    static final String TAB_TITLE = "分层字典";

    private final BurpExtender extender;
    private final BurpViewModel viewModel;
    private final RuleLibraryRepository repository;
    private final GroupTableModel tableModel = new GroupTableModel();

    private JTable table;
    private JTextField nameField;
    private JCheckBox enabledBox;
    private JSpinner minLevel;
    private JSpinner maxLevel;
    private JComboBox<LayeredDictionaryStore.PathStrategy> strategyBox;
    private JComboBox<String> templateBox;
    private JSpinner priority;
    private JSpinner maxRequests;
    private JTextArea entriesArea;
    private JLabel status;
    private String selectedId;

    LayeredDictionaryConfigView(BurpExtender extender, BurpViewModel viewModel,
                                RuleLibraryRepository repository) {
        this.extender = extender;
        this.viewModel = viewModel;
        this.repository = repository;
    }

    void install() {
        if (!SwingUtilities.isEventDispatchThread()) {
            viewModel.onEdt(new Runnable() { public void run() { install(); } });
            return;
        }
        try {
            Object field = BurpExtensionAccess.readField(extender, "configurationTabs");
            if (!(field instanceof JTabbedPane)) return;
            JTabbedPane tabs = (JTabbedPane) field;
            if (findTab(tabs, TAB_TITLE) < 0) {
                tabs.addTab(TAB_TITLE, buildPanel());
            }
            reload();
        } catch (Exception error) {
            log("[CGN] 分层字典页加载失败: " + message(error));
        }
    }

    private JPanel buildPanel() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel header = new JPanel(new BorderLayout(6, 6));
        JLabel title = new JLabel("分层字典扫描 · 按目录层级决定扫哪些字典");
        title.setFont(title.getFont().deriveFont(title.getFont().getStyle() | java.awt.Font.BOLD,
                title.getFont().getSize() + 1.5f));
        header.add(title, BorderLayout.NORTH);
        header.add(new JLabel("字典组决定“扫什么路径”；请求模板决定“怎么请求”；Burp Scope/黑白名单决定“能不能扫”。未配置字典组时自动使用旧字典兼容组。"), BorderLayout.CENTER);
        root.add(header, BorderLayout.NORTH);

        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) loadSelectedIntoEditor();
        });
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("字典组"));

        JPanel editor = buildEditor();
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScroll, editor);
        split.setResizeWeight(0.44);
        root.add(split, BorderLayout.CENTER);

        status = new JLabel("分层字典配置未加载。");
        root.add(status, BorderLayout.SOUTH);
        return root;
    }

    private JPanel buildEditor() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createTitledBorder("字典组编辑"));

        JPanel form = new JPanel(new GridLayout(0, 2, 6, 6));
        nameField = new JTextField();
        enabledBox = new JCheckBox("启用", true);
        minLevel = new JSpinner(new SpinnerNumberModel(1, 0, LayeredDictionaryStore.MAX_LEVEL, 1));
        maxLevel = new JSpinner(new SpinnerNumberModel(3, 0, LayeredDictionaryStore.MAX_LEVEL, 1));
        strategyBox = new JComboBox<LayeredDictionaryStore.PathStrategy>(LayeredDictionaryStore.PathStrategy.values());
        strategyBox.setRenderer((list, value, index, selected, focused) -> new JLabel(value == null ? "" : value.label));
        templateBox = new JComboBox<String>();
        priority = new JSpinner(new SpinnerNumberModel(10, -999, 999, 1));
        maxRequests = new JSpinner(new SpinnerNumberModel(LayeredDictionaryStore.DEFAULT_MAX_REQUESTS, 1, 50000, 50));

        form.add(new JLabel("组名")); form.add(nameField);
        form.add(new JLabel("状态")); form.add(enabledBox);
        form.add(new JLabel("最小层级")); form.add(minLevel);
        form.add(new JLabel("最大层级")); form.add(maxLevel);
        form.add(new JLabel("路径策略")); form.add(strategyBox);
        form.add(new JLabel("关联模板")); form.add(templateBox);
        form.add(new JLabel("优先级")); form.add(priority);
        form.add(new JLabel("本组最大请求数")); form.add(maxRequests);
        root.add(form, BorderLayout.NORTH);

        entriesArea = new JTextArea(18, 48);
        entriesArea.setLineWrap(false);
        JScrollPane entryScroll = new JScrollPane(entriesArea);
        entryScroll.setBorder(BorderFactory.createTitledBorder("字典内容（一行一个，# 开头为注释）"));
        root.add(entryScroll, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton newRoot = new JButton("新建根目录组");
        newRoot.addActionListener(event -> newGroup("根目录入口", 1, 1, LayeredDictionaryStore.PathStrategy.ROOT));
        buttons.add(newRoot);
        JButton newApi = new JButton("新建接口二/三级组");
        newApi.addActionListener(event -> newGroup("API 接口路径", 2, 3, LayeredDictionaryStore.PathStrategy.CURRENT));
        buttons.add(newApi);
        JButton save = new JButton("保存组");
        save.addActionListener(event -> saveCurrent());
        buttons.add(save);
        JButton delete = new JButton("删除组");
        delete.addActionListener(event -> deleteCurrent());
        buttons.add(delete);
        JButton importButton = new JButton("导入字典");
        importButton.addActionListener(event -> importEntries());
        buttons.add(importButton);
        JButton exportButton = new JButton("导出字典");
        exportButton.addActionListener(event -> exportEntries());
        buttons.add(exportButton);
        JButton reload = new JButton("刷新");
        reload.addActionListener(event -> reload());
        buttons.add(reload);
        root.add(buttons, BorderLayout.SOUTH);
        return root;
    }

    private void reload() {
        if (!SwingUtilities.isEventDispatchThread()) {
            viewModel.onEdt(new Runnable() { public void run() { reload(); } });
            return;
        }
        try {
            refreshTemplateBox();
            List<LayeredDictionaryStore.DictionaryGroup> groups = repository.effectiveDictionaryGroups();
            tableModel.setGroups(groups);
            if (!groups.isEmpty()) {
                table.getSelectionModel().setSelectionInterval(0, 0);
            } else {
                selectedId = null;
                clearEditor();
            }
            setStatus("已加载 " + groups.size() + " 个字典组。" + (hasOnlyLegacy(groups)
                    ? " 当前为旧字典兼容组；保存任意自定义组后将启用分层策略。" : ""));
        } catch (Exception error) {
            setStatus("加载失败：" + message(error));
        }
    }

    private void refreshTemplateBox() {
        List<String> names = new ArrayList<String>();
        names.add("全部模板");
        try {
            Object result = BurpExtensionAccess.invokePrivate(extender, "snapshotRequestGroups",
                    new Class<?>[0], new Object[0]);
            if (result instanceof List<?>) {
                for (Object group : (List<?>) result) {
                    String name = BurpExtensionAccess.readStringField(group, "name").trim();
                    if (!name.isEmpty() && !names.contains(name)) names.add(name);
                }
            }
        } catch (Exception ignored) { }
        String current = templateBox == null || templateBox.getSelectedItem() == null
                ? "全部模板" : String.valueOf(templateBox.getSelectedItem());
        templateBox.removeAllItems();
        for (String name : names) templateBox.addItem(name);
        templateBox.setSelectedItem(names.contains(current) ? current : "全部模板");
    }

    private void loadSelectedIntoEditor() {
        int row = table == null ? -1 : table.getSelectedRow();
        LayeredDictionaryStore.DictionaryGroup group = tableModel.at(row);
        if (group == null) return;
        selectedId = group.legacyFallback ? null : group.id;
        nameField.setText(group.legacyFallback ? group.name + "（只读，保存后会创建自定义组）" : group.name);
        enabledBox.setSelected(group.enabled);
        minLevel.setValue(group.minLevel);
        maxLevel.setValue(group.maxLevel);
        strategyBox.setSelectedItem(group.strategy);
        templateBox.setSelectedItem(group.templateName.isEmpty() ? "全部模板" : group.templateName);
        priority.setValue(group.priority);
        maxRequests.setValue(group.maxRequests);
        entriesArea.setText(joinLines(group.entries));
        entriesArea.setCaretPosition(0);
    }

    private void clearEditor() {
        selectedId = null;
        nameField.setText("");
        enabledBox.setSelected(true);
        minLevel.setValue(1);
        maxLevel.setValue(3);
        strategyBox.setSelectedItem(LayeredDictionaryStore.PathStrategy.CURRENT);
        templateBox.setSelectedItem("全部模板");
        priority.setValue(10);
        maxRequests.setValue(LayeredDictionaryStore.DEFAULT_MAX_REQUESTS);
        entriesArea.setText("");
    }

    private void newGroup(String name, int min, int max, LayeredDictionaryStore.PathStrategy strategy) {
        selectedId = null;
        nameField.setText(name);
        enabledBox.setSelected(true);
        minLevel.setValue(min);
        maxLevel.setValue(max);
        strategyBox.setSelectedItem(strategy);
        templateBox.setSelectedItem("全部模板");
        priority.setValue(10);
        maxRequests.setValue(LayeredDictionaryStore.DEFAULT_MAX_REQUESTS);
        entriesArea.setText(defaultEntries(name));
        setStatus("已创建草稿：保存后才会生效。旧字典不会被覆盖。 ");
    }

    private void saveCurrent() {
        try {
            List<String> entries = LayeredDictionaryStore.sanitizeEntries(lines(entriesArea.getText()));
            if (entries.isEmpty()) {
                JOptionPane.showMessageDialog(null, "字典内容不能为空。", "CGN 分层字典", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String template = String.valueOf(templateBox.getSelectedItem());
            if ("全部模板".equals(template)) template = "";
            LayeredDictionaryStore.DictionaryGroup group = new LayeredDictionaryStore.DictionaryGroup(
                    selectedId == null ? UUID.randomUUID().toString() : selectedId,
                    cleanName(nameField.getText()), enabledBox.isSelected(), intValue(minLevel), intValue(maxLevel),
                    (LayeredDictionaryStore.PathStrategy) strategyBox.getSelectedItem(), template,
                    intValue(priority), intValue(maxRequests), entries, false);
            repository.addOrUpdateDictionaryGroup(group);
            selectedId = group.id;
            setStatus("已保存字典组：" + group.summary());
            viewModel.refreshLegacySnapshotFromEdt();
            reload();
            selectById(group.id);
        } catch (Exception error) {
            setStatus("保存失败：" + message(error));
        }
    }

    private void deleteCurrent() {
        if (selectedId == null) {
            setStatus("当前是旧字典兼容组或未保存草稿，无法删除。 ");
            return;
        }
        if (JOptionPane.showConfirmDialog(null, "确认删除当前字典组？旧字典不会受影响。", "CGN 分层字典",
                JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        try {
            repository.deleteDictionaryGroup(selectedId);
            selectedId = null;
            setStatus("已删除字典组。 ");
            viewModel.refreshLegacySnapshotFromEdt();
            reload();
        } catch (Exception error) {
            setStatus("删除失败：" + message(error));
        }
    }

    private void importEntries() {
        if (selectedId == null) {
            setStatus("请先保存字典组，再导入字典文件。 ");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return;
        try {
            int count = repository.importDictionaryGroupEntries(selectedId, chooser.getSelectedFile());
            setStatus("导入完成，当前组共 " + count + " 条。 ");
            viewModel.refreshLegacySnapshotFromEdt();
            reload();
            selectById(selectedId);
        } catch (Exception error) {
            setStatus("导入失败：" + message(error));
        }
    }

    private void exportEntries() {
        if (selectedId == null) {
            setStatus("旧字典兼容组请在原“字典/规则库”页导出，或先另存为自定义组。 ");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;
        try {
            repository.exportDictionaryGroupEntries(selectedId, chooser.getSelectedFile());
            setStatus("导出完成：" + chooser.getSelectedFile().getName());
        } catch (Exception error) {
            setStatus("导出失败：" + message(error));
        }
    }

    private void selectById(String id) {
        if (id == null) return;
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            LayeredDictionaryStore.DictionaryGroup group = tableModel.at(i);
            if (group != null && id.equals(group.id)) {
                table.getSelectionModel().setSelectionInterval(i, i);
                return;
            }
        }
    }

    private boolean hasOnlyLegacy(List<LayeredDictionaryStore.DictionaryGroup> groups) {
        return groups.size() == 1 && groups.get(0).legacyFallback;
    }

    private String defaultEntries(String name) {
        if (name.contains("根")) return "admin\nlogin\napi\nswagger-ui\nactuator";
        return "user\nadmin\norder\nconfig\nsystem";
    }

    private String cleanName(String raw) {
        String value = raw == null ? "" : raw.replace("（只读，保存后会创建自定义组）", "").trim();
        return value.isEmpty() ? "自定义字典组" : value;
    }

    private void setStatus(String value) { if (status != null) status.setText(value); }
    private void log(String value) { CgnReliability.log(extender, value); }
    private int intValue(JSpinner spinner) { return ((Number) spinner.getValue()).intValue(); }
    private String message(Throwable error) { return error == null ? "unknown" : String.valueOf(error.getMessage()); }

    private int findTab(JTabbedPane tabs, String title) {
        for (int i = 0; i < tabs.getTabCount(); i++) if (title.equals(tabs.getTitleAt(i))) return i;
        return -1;
    }

    private List<String> lines(String text) {
        List<String> values = new ArrayList<String>();
        if (text != null) Collections.addAll(values, text.split("\\R"));
        return values;
    }

    private String joinLines(List<String> entries) {
        StringBuilder builder = new StringBuilder();
        if (entries != null) {
            for (String entry : entries) {
                if (builder.length() > 0) builder.append('\n');
                builder.append(entry);
            }
        }
        return builder.toString();
    }

    private static final class GroupTableModel extends AbstractTableModel {
        private final String[] columns = {"启用", "字典组", "层级", "路径策略", "条数", "模板", "优先级"};
        private List<LayeredDictionaryStore.DictionaryGroup> groups = Collections.emptyList();

        void setGroups(List<LayeredDictionaryStore.DictionaryGroup> values) {
            groups = values == null ? Collections.<LayeredDictionaryStore.DictionaryGroup>emptyList()
                    : new ArrayList<LayeredDictionaryStore.DictionaryGroup>(values);
            fireTableDataChanged();
        }

        LayeredDictionaryStore.DictionaryGroup at(int row) {
            return row < 0 || row >= groups.size() ? null : groups.get(row);
        }

        public int getRowCount() { return groups.size(); }
        public int getColumnCount() { return columns.length; }
        public String getColumnName(int column) { return columns[column]; }
        public Object getValueAt(int row, int column) {
            LayeredDictionaryStore.DictionaryGroup group = groups.get(row);
            switch (column) {
                case 0: return group.enabled ? "是" : "否";
                case 1: return group.name + (group.legacyFallback ? "（兼容）" : "");
                case 2: return group.levelText();
                case 3: return group.strategy.label;
                case 4: return group.entries.size();
                case 5: return group.templateName.isEmpty() ? "全部" : group.templateName;
                case 6: return group.priority;
                default: return "";
            }
        }
    }
}
