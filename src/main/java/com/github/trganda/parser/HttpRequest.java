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
public class HttpRequest {

    public static Map<String, String> defaultHeader =
            Stream.of(
                    new AbstractMap.SimpleEntry<>("Host", "localhost"),
                    new AbstractMap.SimpleEntry<>("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36 Edg/104.0.1293.47"),
                    new AbstractMap.SimpleEntry<>("Connection", "close"),
                    new AbstractMap.SimpleEntry<>("Accept", "*/*")).
                    collect(Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue));

    private String method;
    private String uri;
    private String version;
    private Map<String, String> headers;
    private String body;

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
        return "HttpRequest{" +
                "method='" + method + '\'' +
                ", uri='" + uri + '\'' +
                ", version='" + version + '\'' +
                ", headers=" + headers +
                ", body='" + body + '\'' +
                '}';
    }
}
