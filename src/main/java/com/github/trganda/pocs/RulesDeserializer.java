package com.github.trganda.pocs;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.type.MapType;
import com.fasterxml.jackson.databind.type.TypeBindings;

import java.io.IOException;
import java.util.Map;

public class RulesDeserializer extends JsonDeserializer<Rules> {
    @Override
    public Rules deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {

        Rules rule = new Rules();

        JavaType keyType = ctxt.getTypeFactory().constructType(String.class);
        JavaType valType = ctxt.getTypeFactory().constructType(Rules.RuleItem.class);

        TypeBindings typeBindings = TypeBindings.emptyBindings();

        MapType mapType = MapType.construct(Map.class, typeBindings,
                ctxt.getTypeFactory().constructType(Object.class), (JavaType[])null, keyType, valType);

        rule.rules = ctxt.readValue(p, mapType);

        return rule;
    }
}
