package com.github.trganda.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.github.trganda.eval.Evaluation;
import com.github.trganda.pocs.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.github.trganda.parser.HttpRequest.defaultHeader;
import static java.util.regex.Pattern.MULTILINE;

public class PocsParser {

    private final File file;
    private ObjectMapper mapper;

    public PocsParser(File file) {
        this.file = file;
        init();
    }

    private void init() {
        mapper = new ObjectMapper(new YAMLFactory());

        SimpleModule simpleModule = new SimpleModule();
        simpleModule.addDeserializer(Sets.class, new SetJsonDeserializer());
        simpleModule.addDeserializer(Rules.class, new RulesDeserializer());

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
        Map<String, Object> valMap = evaluation.evalSet(pocs.set);

        List<HttpRequest> httpRequests = new ArrayList<>();

        for (Map.Entry<String, Rules.RuleItem> ruleItemEntry : pocs.rules.rules.entrySet()) {
            Rules.Request req = ruleItemEntry.getValue().request;
            Map<String, byte[]> headers = defaultHeader;

            /*
             * For each set variable value
             * Step:
             *     * replace all string variable
             *     * process byte type variable and convert them with string variable to byte array
             */
            for (Map.Entry<String, Object> val : valMap.entrySet()) {
                if (val.getValue() instanceof String) {
                    String stringVal = (String) val.getValue();

                    req.path = req.path.replaceAll("\\{\\{" + val.getKey() + "}}", stringVal);
                    req.body = req.body.replaceAll("\\{\\{" + val.getKey() + "}}", stringVal);

                    if (req.headers == null) {
                        continue;
                    }

                    for (Map.Entry<String, String> header : req.headers.entrySet()) {
                        if (!header.getValue().contains("{{" + val.getKey() + "}}")) {
                            continue;
                        }
                        header.setValue(header.getValue().replaceAll("\\{\\{" + val.getKey() + "}}", stringVal));
                    }
                }
            }

            byte[] path = toBytes(req.path, valMap);
            byte[] body = toBytes(req.body, valMap);

            if (req.headers != null) {
                if (req.method.equals("POST")) {
                    headers.put("Content-Length", String.valueOf(body.length).getBytes(StandardCharsets.UTF_8));
                }

                for (Map.Entry<String, String> header : req.headers.entrySet()) {
                    headers.put(header.getKey(), toBytes(header.getValue(), valMap));
                }
            }

            httpRequests.add(new HttpRequest(
                    req.method, path, "1.1", headers, body));
        }

        return httpRequests;
    }

    private byte[] toBytes(String valueFor, Map<String, Object> valMap) {
        String bStrPattern = "\\{\\{([\\w\\d]+)}}";
        Pattern pattern = Pattern.compile(bStrPattern, MULTILINE);
        Matcher matcher = pattern.matcher(valueFor);

        List<Byte> bytes = new LinkedList<>();

        int matcher_start = 0;
        int start_idx = 0;
        int end_idx = 0;
        while (matcher.find(matcher_start)){
            end_idx = matcher.start(0);
            byte[] b = valueFor.substring(start_idx, end_idx).getBytes(StandardCharsets.UTF_8);
            start_idx = end_idx + matcher.group(0).length();
            end_idx = start_idx;
            for (byte bt : b) {
                bytes.add(bt);
            }

            Object value = valMap.get(matcher.group(1));
            if (value instanceof byte[]) {
                for (byte bt : (byte[])value) {
                    bytes.add(bt);
                }
            }

            matcher_start = matcher.end();
        }

        if (end_idx < valueFor.length()) {
            byte[] b = valueFor.substring(end_idx).getBytes(StandardCharsets.UTF_8);
            for (byte bt : b) {
                bytes.add(bt);
            }
        }

        byte[] ret = new byte[bytes.size()];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = bytes.get(i);
        }

        return ret;
    }
}
