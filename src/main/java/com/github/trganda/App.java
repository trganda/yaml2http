package com.github.trganda;

import com.github.trganda.parser.HttpRequest;
import com.github.trganda.parser.PocsParser;
import com.github.trganda.pocs.*;
import org.apache.commons.cli.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class App {

    public static void main(String[] args) throws IOException, ParseException {
        Options options = new Options();
        options.addOption("p", "path", true, "Path to poc file.");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("path")) {
            String path = cmd.getOptionValue("path");
            PocsParser pocsParser = new PocsParser(new File(path));
            Pocs pocs = pocsParser.readPocs();

            List<HttpRequest> httpRequestList = pocsParser.toHttpRequests(pocs);

            for (HttpRequest httpRequest : httpRequestList) {
                System.out.println(httpRequest.toString());
            }
        }

    }
}
