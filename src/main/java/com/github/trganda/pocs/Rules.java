package com.github.trganda.pocs;

import java.util.Map;

public class Rules {

    public Map<String, RuleItem> ruleItems;

    public static class RuleItem {
        public Request request;
        public String expression;

        @Override
        public String toString() {
            return "RuleItem{" +
                    "request=" + request +
                    ", expression='" + expression + '\'' +
                    '}';
        }
    }

    public static class Request {
        public String method;
        public String path;
        public Map<String, String> headers;
        public String body;

        @Override
        public String toString() {
            return "Request{" +
                    "method='" + method + '\'' +
                    ", path='" + path + '\'' +
                    ", headers=" + headers +
                    ", body='" + body + '\'' +
                    '}';
        }
    }

    @Override
    public String toString() {
        return "Rules{" +
                "ruleItems=" + ruleItems +
                '}';
    }
}
