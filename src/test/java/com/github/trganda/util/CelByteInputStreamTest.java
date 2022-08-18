package com.github.trganda.util;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class CelByteInputStreamTest {

    @Test
    public void readTest() throws IOException {
        String str = "b\"\\xac\\xed\\x00\\x05sr\\x00\\x11java.util.HashMap\\x05\\a\\xda\\xc1\\xc3\\x16`\\xd1\\x03\\x00\\x02F\\x00\\nloadFactorI\\x00\\tthresholdxp?@\\x00\\x00\\x00\\x00\\x00\\fw\\b\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x02t\\x00\\tFILE_NAMEt\\x00\\t\"";
        ByteArrayInputStream bis = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));

        CelBytesInputStream celBytesInputStream = new CelBytesInputStream(bis);
        celBytesInputStream.process();

        System.out.println(celBytesInputStream.getBufString());
    }
}
