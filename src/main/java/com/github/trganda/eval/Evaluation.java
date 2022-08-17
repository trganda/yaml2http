package com.github.trganda.eval;

import com.github.trganda.functions.GlobalMethodResolver;
import com.github.trganda.pocs.Sets;
import com.github.trganda.util.Util;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Evaluation {
    private final ExpressionParser parser;
    private final SimpleEvaluationContext.Builder builder;
    private final EvaluationContext context;

    public Evaluation() {
        parser = new SpelExpressionParser();
        builder = SimpleEvaluationContext.forReadOnlyDataBinding().withMethodResolvers();
        init();
        context = builder.build();
    }

    private void init() {
        builder.withMethodResolvers(new GlobalMethodResolver());
    }

    public String eval(String expression) {
        return parser.parseExpression(expression).getValue(context, "", String.class);
    }

    public Map<String, String> evalSet(Sets sets) {

        Map<String, String> ret = new LinkedHashMap<>();

        for (Map.Entry<String, String> entry : sets.setItem.entrySet()) {
            String key = entry.getKey();
            String value = prepare(entry.getValue());
            ret.put(key, eval(value));
        }

        return ret;
    }

    private String prepare(String expression) {
        String bStrPattern = "b(\".*?\")";
        Pattern pattern = Pattern.compile(bStrPattern);

        Matcher matcher = pattern.matcher(expression);

        if (matcher.find()) {
            return Util.hex2Unicode(matcher.group(1));
        }

        return expression;
    }
}
