package com.github.trganda.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.github.trganda.eval.Evaluation;
import com.github.trganda.pocs.*;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.github.trganda.parser.HttpRequest.defaultHeader;

public class PocsParser {

    private File file;
    private ObjectMapper mapper;

    public PocsParser(File file) {
        this.file = file;
        init();
    }

    private void init() {
        mapper = new ObjectMapper(new YAMLFactory());

        SimpleModule simpleModule = new SimpleModule();
        simpleModule.addDeserializer(Sets.class, new SetJsonDeserializer());
        simpleModule.addDeserializer(Rules.class, new RuleDeserializer());
        simpleModule.addDeserializer(Rules.RuleItem.class, new RuleItemDeserializer());

        mapper.registerModule(simpleModule);
        mapper.findAndRegisterModules();
    }

    public Pocs readPocs() throws IOException {
        return mapper.readValue(file, Pocs.class);
    }

    public List<HttpRequest> toHttpRequests(Pocs pocs) {
        if (pocs == null) {
            return null;
        }

        Evaluation evaluation = new Evaluation();
        Map<String, String> valMap = evaluation.evalSet(pocs.set);

        List<HttpRequest> httpRequests = new ArrayList<>();

        for (Map.Entry<String, Rules.RuleItem> ruleItemEntry : pocs.rules.ruleItems.entrySet()) {
            Rules.Request req = ruleItemEntry.getValue().request;
            Map<String, String> theader = defaultHeader;

            for (Map.Entry<String, String> val : valMap.entrySet()) {
                req.path = req.path.replaceAll("\\{\\{" + val.getKey() + "}}", val.getValue());
                req.body = req.body.replaceAll("\\{\\{" + val.getKey() + "}}", val.getValue());

                for (Map.Entry<String, String> header : req.headers.entrySet()) {
                    if (!header.getValue().contains("{{" + val.getKey() + "}}")) {
                        continue;
                    }
                    header.setValue(header.getValue().replaceAll("\\{\\{" + val.getKey() + "}}", val.getValue()));
                }
            }

            theader.putAll(req.headers);
            httpRequests.add(new HttpRequest(
                    req.method, req.path, "1.1", theader, req.body));
        }

        return httpRequests;
    }
}
