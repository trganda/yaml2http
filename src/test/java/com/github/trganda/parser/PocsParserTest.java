package com.github.trganda.parser;

import com.github.trganda.App;
import com.github.trganda.pocs.Pocs;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class PocsParserTest {
    @Test
    public void toBytesTest() throws IOException {
        File dirs = new File("yamlpocs");
        if (!dirs.exists() || !dirs.isDirectory()) {
            throw new IllegalArgumentException();
        }

        for (File file : dirs.listFiles()) {
            if (file.isFile() && file.getName().substring(file.getName().lastIndexOf(".") + 1).equals("yaml")) {
                PocsParser parser = new PocsParser(file);

                Pocs pocs = parser.readPocs();
                List<HttpRequest> httpRequestList = parser.toHttpRequests(pocs);

                for (HttpRequest httpRequest : httpRequestList) {
                    System.out.println(httpRequest.toString());
                }
            }
        }
    }
}
