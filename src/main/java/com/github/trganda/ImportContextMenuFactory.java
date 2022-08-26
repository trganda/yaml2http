package com.github.trganda;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

import static burp.IBurpExtenderCallbacks.TOOL_REPEATER;

public class ImportContextMenuFactory implements IContextMenuFactory {

    private final IBurpExtenderCallbacks callbacks;

    public ImportContextMenuFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

        List<JMenuItem> menus = new ArrayList<>();
        if (invocation.getToolFlag() == TOOL_REPEATER) {

            JMenuItem jMenuItem = new JMenuItem("Import Poc(Yaml Format)", null);
            jMenuItem.setActionCommand("import");
            jMenuItem.addActionListener(new ImportActionListener(callbacks));

            menus.add(jMenuItem);
        }
        return menus;
    }
}
