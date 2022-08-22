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
        PocsParser parser = new PocsParser(new File(
                App.class.getClassLoader().getResource(
                        "poc-yaml-yonyou-nc-arbitrary-file-upload.yaml").getPath()));

        Pocs pocs = parser.readPocs();
        List<HttpRequest> httpRequestList = parser.toHttpRequests(pocs);

        for (HttpRequest httpRequest : httpRequestList) {
            System.out.println(httpRequest.getTotal());
        }
    }
}
