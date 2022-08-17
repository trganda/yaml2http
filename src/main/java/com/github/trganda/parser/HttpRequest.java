package com.github.trganda.parser;

import java.util.AbstractMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * type HttpRequest struct {
 * 	Method  string
 * 	URI     string
 * 	Version string
 * 	Headers map[string]string
 * 	Body    string
 * }
 */
public final class HttpRequest {

    public static Map<String, String> defaultHeader =
            Stream.of(
                    new AbstractMap.SimpleEntry<>("Host", "localhost"),
                    new AbstractMap.SimpleEntry<>("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36 Edg/104.0.1293.47"),
                    new AbstractMap.SimpleEntry<>("Connection", "close"),
                    new AbstractMap.SimpleEntry<>("Accept", "*/*")).
                    collect(Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue));

    private final String method;
    private final String uri;
    private final String version;
    private final Map<String, String> headers;
    private final String body;

    public HttpRequest(String method, String uri,
                       String version, Map<String, String> headers, String body) {
        this.method = method;
        this.uri = uri;
        this.version = version;
        this.headers = headers;
        this.body = body;
    }

    @Override
    public String toString() {

        StringBuilder requestString = new StringBuilder();
        requestString.append(method).append(" ").append(uri).append(" HTTP/").append(version).append("\n");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            requestString.append(header.getKey()).append(": ").append(header.getValue()).append("\n");
        }
        requestString.append("\n");
        if (body != null && !body.isEmpty()) {
            requestString.append(body).append("\n");
        }
        requestString.append("\n");

        return requestString.toString();
    }
}
