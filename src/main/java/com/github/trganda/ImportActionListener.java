package com.github.trganda;

import burp.IBurpExtenderCallbacks;
import com.github.trganda.parser.HttpRequest;
import com.github.trganda.parser.PocsParser;
import com.github.trganda.pocs.Pocs;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.List;
import java.util.Objects;

public class ImportActionListener implements ActionListener {

    private final IBurpExtenderCallbacks callbacks;
    private final JFileChooser chooser;
    private File last;

    public ImportActionListener(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.last = null;

        chooser = new JFileChooser();
        chooser.addChoosableFileFilter(new JavaFileFilter("yaml"));
        chooser.addChoosableFileFilter(new JavaFileFilter("yml"));
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (Objects.equals(e.getActionCommand(), "import")) {
            if (last != null)
                chooser.setCurrentDirectory(last);
            chooser.showOpenDialog(chooser);
            File file = chooser.getSelectedFile().getAbsoluteFile();
            if (file.exists() && file.isFile()) {
                last = file.getParentFile();
                try {
                    PocsParser parser = new PocsParser(file);
                    Pocs pocs = parser.readPocs();
                    List<HttpRequest> httpRequestList = parser.toHttpRequests(pocs);

                    for (HttpRequest httpRequest : httpRequestList) {
                        callbacks.sendToRepeater("localhost", 80, false,
                                httpRequest.getTotal(), pocs.name);
                    }
                } catch (IOException ex) {
                    callbacks.issueAlert(ex.toString());
                }
            } else if (file.isDirectory()) {
                last = file;
            }
        }
    }
}
