package com.github.trganda.eval;

import com.github.trganda.functions.GlobalMethodResolver;
import com.github.trganda.pocs.Sets;
import com.github.trganda.util.CelBytesInputStream;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

    public <T> T  eval(String expression, Class<T> desiredResultType) {
        return parser.parseExpression(expression).getValue(context, "", desiredResultType);
    }

    /**
     * Eval each value of sets with spel.
     * @param sets, the variable that need to be eval.
     * @return evaluated result.
     */
    public Map<String, String> evalSet(Sets sets) {

        Map<String, String> ret = new LinkedHashMap<>();

        for (Map.Entry<String, String> entry : sets.setItem.entrySet()) {
            String key = entry.getKey();
            String value = prepare(entry.getValue());
            ret.put(key, eval(value));
        }

        return ret;
    }

    /**
     * Convert the byte string of golang to a java String
     * @param expression, raw golang byte string.
     * @return converted java string.
     */
    private String prepare(String expression) {
        String bStrPattern = "b(\".*?\")";
        Pattern pattern = Pattern.compile(bStrPattern);

        Matcher matcher = pattern.matcher(expression);

        int matcher_start = 0;
        while (matcher.find(matcher_start)){
            ByteArrayInputStream bis = new ByteArrayInputStream(matcher.group(0).getBytes(StandardCharsets.UTF_8));

            try {
                CelBytesInputStream celBytesInputStream = new CelBytesInputStream(bis);
                celBytesInputStream.readCelBytes();

                expression = expression.replace(matcher.group(0), celBytesInputStream.getBufString());
                matcher_start = matcher.end();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

        return expression;
    }
}
