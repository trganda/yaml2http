package com.github.trganda;

import javax.swing.filechooser.FileFilter;
import java.io.File;

class JavaFileFilter extends FileFilter {
    String ext;

    public JavaFileFilter(String ext) {
        this.ext = ext;
    }

    /**
     * Accept yaml or yml file.
     * @param file file object.
     * @return true if file is a directory or accept the file extension with .yaml/.yml
     */
    public boolean accept(File file) {
        if (file.isDirectory()) {
            return true;
        }
        String fileName = file.getName();
        int index = fileName.lastIndexOf('.');
        if (index > 0 && index < fileName.length() - 1) {
            String extension = fileName.substring(index + 1).toLowerCase();
            if (extension.equals(ext))
                return true;
        }
        return false;
    }

    public String getDescription() {
        if (ext.equals("yaml"))
            return "Poc(*.yaml)";
        if (ext.equals("yml"))
            return "Poc(*.yml)";
        return "";
    }
}