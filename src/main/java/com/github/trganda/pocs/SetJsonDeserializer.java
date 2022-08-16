package com.github.trganda.pocs;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class SetJsonDeserializer extends JsonDeserializer<Sets> {
    @Override
    public Sets deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
        Map mv = new LinkedHashMap<>();
        mv = ctxt.readValue(p, mv.getClass());

        Sets sets = new Sets();
        sets.setItem = mv;

        return sets;
    }
}
