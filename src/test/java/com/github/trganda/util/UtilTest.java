package com.github.trganda.util;

import com.github.trganda.eval.Evaluation;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class UtilTest {

    @Test
    public void toBytesValueTest() throws IOException {
        byte[] buf = new byte[] {80, 75, 3, 4, 20, 0, 0, 0, 8, 0, 29, 91, 25, 85, 61, 81, 107, 77, 5, 0, 0, 0, 3, 0, 0, 0, 14, 0, 0, 0, 46, 46, 47, 46, 46, 47, 46, 46, 47, 49, 46, 116, 120, 116, 51, 52, 52, 4, 0, 80, 75, 1, 2, 20, 3, 20, 0, 0, 0, 8, 0, 29, 91, 25, 85, 61, 81, 107, 77, 5, 0, 0, 0, 3, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -128, 1, 0, 0, 0, 0, 46, 46, 47, 46, 46};
        String want = "b\"PK\\x03\\x04\\x14\\x00\\x00\\x00\\x08\\x00\\x1d[\\x19U=QkM\\x05\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\x0e\\x00\\x00\\x00../../../1.txt344\\x04\\x00PK\\x01\\x02\\x14\\x03\\x14\\x00\\x00\\x00\\x08\\x00\\x1d[\\x19U=QkM\\x05\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\x0e\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x80\\x01\\x00\\x00\\x00\\x00../..\"";
        String bytesValue = Util.toBytesValue(buf);

        assert bytesValue.equals(want);
    }
}
