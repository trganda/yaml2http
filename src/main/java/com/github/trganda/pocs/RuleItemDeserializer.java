package com.github.trganda.pocs;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;

public class RuleItemDeserializer extends JsonDeserializer<Rules.RuleItem> {
    @Override
    public Rules.RuleItem deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
        return null;
    }
}
