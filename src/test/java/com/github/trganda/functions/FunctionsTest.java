package com.github.trganda.functions;

import com.github.trganda.eval.Evaluation;
import com.github.trganda.util.CelBytesInputStream;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class FunctionsTest {

    @Test
    public void desTest() throws IOException {
        String cipherText = "b\"\\x8A\\xD2\\xF1\\xD4\\x98\\x7E\\x70\\x05\\x53\\x6E\\x9A\\x97\\xC0\\xEB\\x39\\xE3\\x69\\x90\\xFD\\x49\\x4C\\xDF\\xC7\\x26\\x9F\\xD2\\x3F\\x76\\xCD\\x96\\x1E\\xE8\\xFB\\xB4\\x4D\\xA3\\x82\\x1B\\x48\\x9C\\x4C\\xC7\\xA1\\x3F\\x35\\x0D\\xA0\\x62\\x09\\xFB\\xB2\\x17\\x76\\xE7\\x77\\xF6\\xD9\\x7A\\x7A\\x04\\x3C\\x4E\\x3E\\x3F\\x0D\\x3F\\x1D\\xB7\\xC4\\xC4\\xFB\\x3F\\x26\\x95\\x94\\x57\\x51\\x3F\\x35\\xB7\\xBC\\xC4\\x92\\xBB\\xF4\\x62\\x82\\xB4\\x94\\x74\\x25\\xCD\\xDD\\x5C\\x7A\\x73\\xE6\\x77\\x40\\x3F\\x0A\\x3F\\xF7\\x42\\xE2\\x46\\xFE\\xC7\\xC7\\x43\\x53\\x29\"";
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(cipherText.getBytes(StandardCharsets.UTF_8));
            CelBytesInputStream celBytesInputStream = new CelBytesInputStream(bis);
            celBytesInputStream.readCelBytes();

            Evaluation evaluation = new Evaluation();
            byte[] ret = evaluation.eval(celBytesInputStream.getBufString(), byte[].class);

            System.out.println(new String(Functions.desdecode(ret, "1z2x3c4v5b6n"), "GBK"));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


}
