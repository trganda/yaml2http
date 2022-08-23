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
                        "yamlpocs/poc-yaml-ecology9-beanshell-rce.yaml"));

        Pocs pocs = parser.readPocs();
        List<HttpRequest> httpRequestList = parser.toHttpRequests(pocs);

        for (HttpRequest httpRequest : httpRequestList) {
            System.out.println(httpRequest.toString());
        }
    }
}
