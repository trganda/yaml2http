package com.github.trganda;

import com.github.trganda.parser.HttpRequest;
import com.github.trganda.parser.PocsParser;
import com.github.trganda.pocs.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class App {

    public static void main(String[] args) throws IOException {
        PocsParser parser = new PocsParser(new File(App.class.getClassLoader().getResource("poc-yaml-yonyou-nc-arbitrary-file-upload.yaml").getPath()));

        Pocs pocs = parser.readPocs();
        List<HttpRequest> httpRequestList = parser.toHttpRequests(pocs);

        for (HttpRequest httpRequest : httpRequestList) {
            System.out.println(httpRequest);
        }
    }
}
