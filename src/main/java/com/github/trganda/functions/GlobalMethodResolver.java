package com.github.trganda.functions;

import org.springframework.expression.spel.support.ReflectiveMethodResolver;

import java.lang.reflect.Method;

public class GlobalMethodResolver extends ReflectiveMethodResolver {

    @Override
    protected Method[] getMethods(Class<?> type) {
        try {
            return new Method[] {
                    Functions.class.getDeclaredMethod("randomInt", Integer.TYPE, Integer.TYPE),
                    Functions.class.getDeclaredMethod("base64", String.class),
                    Functions.class.getDeclaredMethod("base64", byte[].class),
                    Functions.class.getDeclaredMethod("md5", String.class),
                    Functions.class.getDeclaredMethod("md5", byte[].class),
                    Functions.class.getDeclaredMethod("base64Decode", String.class),
                    Functions.class.getDeclaredMethod("base64Decode", byte[].class),
                    Functions.class.getDeclaredMethod("urlencode", String.class),
                    Functions.class.getDeclaredMethod("urlencode", byte[].class),
                    Functions.class.getDeclaredMethod("urldecode", String.class),
                    Functions.class.getDeclaredMethod("urldecode", byte[].class),
                    Functions.class.getDeclaredMethod("substr", String.class, int.class, int.class)
            };
        }
        catch (NoSuchMethodException ex) {
            return new Method[0];
        }
    }
    
}
