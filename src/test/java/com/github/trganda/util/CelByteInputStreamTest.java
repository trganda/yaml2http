package com.github.trganda.util;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class CelByteInputStreamTest {

    @Test
    public void readTest() throws IOException {
        String str = "b\".jspt\\x00\\x10TARGET_FILE_PATHt\\x00\\x10./webapps/nc_webx\"";
        ByteArrayInputStream bis = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));

        CelBytesInputStream celBytesInputStream = new CelBytesInputStream(bis);
        celBytesInputStream.process();

        ArrayList<Byte> bytes = celBytesInputStream.getBuf();
        System.out.println(bytes);
    }
}
