package com.github.trganda.util;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;

public class ByteReader extends DataInputStream {


    /**
     * Creates a DataInputStream that uses the specified
     * underlying InputStream.
     *
     * @param in the specified input stream
     */
    public ByteReader(InputStream in) {
        super(in);
    }
}
