package com.github.trganda;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
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
            chooser.showOpenDialog(chooser);
            File file = chooser.getSelectedFile();
            if (file.exists() && file.isFile()) {
                FileInputStream fis = null;
                try {
                    fis = new FileInputStream(file);
                    int size = fis.available();
                    byte[] output = new byte[size];

                    fis.read(output);

                    callbacks.sendToRepeater("localhost", 80, false,
                            output, "");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }

            }
        }
    }
}
