package com.github.trganda.util;

import com.github.trganda.eval.Evaluation;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class CelByteInputStreamTest {

    @Test
    public void readCelBytesTest() throws IOException {
        byte[] want = new byte[]{-84, 127, 7, 8, 12, 10, 13, 9, 11, 92, 63, 34, 39, 96};
        String str = "b\"\\xac\\077\\a\\b\\f\\n\\r\\t\\v\\\\?\\\"\\'\\`\"";
        ByteArrayInputStream bis = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));

        CelBytesInputStream celBytesInputStream = new CelBytesInputStream(bis);
        celBytesInputStream.readCelBytes();

        Evaluation evaluation = new Evaluation();
        byte[] ret = evaluation.eval(celBytesInputStream.getBufString(), byte[].class);
        assert want.length == ret.length;
        for (int i = 0; i < want.length; i++) {
            assert want[i] == ret[i];
        }
    }

}
