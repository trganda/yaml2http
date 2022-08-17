package com.github.trganda;

import burp.IBurpExtenderCallbacks;
import com.github.trganda.parser.HttpRequest;
import com.github.trganda.parser.PocsParser;
import com.github.trganda.pocs.Pocs;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

public class ImportActionListener implements ActionListener {

    private IBurpExtenderCallbacks callbacks;

    public ImportActionListener(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (Objects.equals(e.getActionCommand(), "import")) {
            JFileChooser chooser = new JFileChooser();
            chooser.addChoosableFileFilter(new JavaFileFilter("yaml"));
            chooser.addChoosableFileFilter(new JavaFileFilter("yml"));
            chooser.showOpenDialog(chooser);
            File file = chooser.getSelectedFile().getAbsoluteFile();
            if (file.exists() && file.isFile()) {
                try {
                    PocsParser parser = new PocsParser(file);
                    Pocs pocs = parser.readPocs();
                    List<HttpRequest> httpRequestList = parser.toHttpRequests(pocs);

                    for (HttpRequest httpRequest : httpRequestList) {
                        callbacks.sendToRepeater("localhost", 80, false,
                                httpRequest.toString().getBytes(StandardCharsets.UTF_8), pocs.name);
                    }


                } catch (IOException ex) {
                    callbacks.issueAlert(ex.toString());
                }

            }
        }
    }
}
