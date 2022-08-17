package com.github.trganda.pocs;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.type.MapType;
import com.fasterxml.jackson.databind.type.TypeBindings;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

public class SetJsonDeserializer extends JsonDeserializer<Sets> {
    @Override
    public Sets deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
        JavaType strType = ctxt.getTypeFactory().constructType(String.class);

        TypeBindings typeBindings = TypeBindings.emptyBindings();
        MapType mapType = MapType.construct(Map.class, typeBindings,
                ctxt.getTypeFactory().constructType(Object.class), (JavaType[])null, strType, strType);

        Sets sets = new Sets();
        sets.setItem = ctxt.readValue(p, mapType);

        return sets;
    }
}
