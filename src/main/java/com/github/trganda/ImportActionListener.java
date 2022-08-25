package com.github.trganda;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
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
    private File last;

    public ImportActionListener(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        try {
            this.last = new File(System.getProperty("last.import.dir"));
        } catch (Exception ex) {
            this.last = new File(System.getProperty("user.dir"));
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (Objects.equals(e.getActionCommand(), "import")) {
            JFileChooser chooser = new JFileChooser();
            chooser.addChoosableFileFilter(new JavaFileFilter("yaml"));
            chooser.addChoosableFileFilter(new JavaFileFilter("yml"));
            if (last != null)
                chooser.setCurrentDirectory(last);
            chooser.showOpenDialog(null);
            File file = chooser.getSelectedFile().getAbsoluteFile();
            if (file.exists() && file.isFile()) {
                System.setProperty("last.import.dir", file.getParent());
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
                System.setProperty("last.import.dir", file.getPath());
            }
        }
    }
}
