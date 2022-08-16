package com.github.trganda.pocs;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

public class RuleDeserializer extends JsonDeserializer<Rules> {
    @Override
    public Rules deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {

        Map ruleItems = new LinkedHashMap<>();
        ruleItems = ctxt.readValue(p, ruleItems.getClass());

        Rules rules = new Rules();
        rules.ruleItems = ruleItems;

        return rules;
    }
}
