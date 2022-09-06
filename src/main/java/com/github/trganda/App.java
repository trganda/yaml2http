package com.github.trganda;

import com.github.trganda.parser.HttpRequest;
import com.github.trganda.parser.PocsParser;
import com.github.trganda.pocs.*;
import org.apache.commons.cli.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import com.github.trganda.util.Util;

public class App {

    public static void main(String[] args) throws IOException, ParseException {
        Options options = new Options();
        options.addOption("h", "help", false, "Help info.");
        options.addOption("p", "path", true, "Path to poc file.");
        options.addOption("b", "bytes", true, "Path to file need to be convert, convert the file content as bytes value with b\"\" format.");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("p")) {
            String path = cmd.getOptionValue("p");
            PocsParser pocsParser = new PocsParser(new File(path));
            Pocs pocs = pocsParser.readPocs();

            List<HttpRequest> httpRequestList = pocsParser.toHttpRequests(pocs);

            for (HttpRequest httpRequest : httpRequestList) {
                System.out.println(httpRequest.toString());
            }
        } else if (cmd.hasOption("b")) {
            String path = cmd.getOptionValue("b");
            FileInputStream is = new FileInputStream(path);

            byte[] buf = new byte[is.available()];
            is.read(buf);

            System.out.println(Util.toBytesValue(buf));
        } else {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("yaml2http", options);
        }

    }
}
