package com.github.trganda.parser;

import com.github.trganda.util.Util;

import java.nio.charset.StandardCharsets;
import java.util.*;
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
    private final byte[] uri;
    private final String version;
    private final Map<String, String> headers;
    private final byte[] body;
    private byte[] total;

    public HttpRequest(String method, byte[] uri,
                       String version, Map<String, String> headers, byte[] body) {
        this.method = method;
        this.uri = uri;
        this.version = version;
        this.headers = headers;
        this.body = body;
        total = new byte[0];
    }

    @Override
    public String toString() {
        return new String(getTotal(), StandardCharsets.UTF_8);
    }

    private void toBytes() {
        List<Byte> bytes = new LinkedList<>();

        Util.addAll(bytes, (method + " ").getBytes(StandardCharsets.UTF_8));
        Util.addAll(bytes, uri);
        Util.addAll(bytes, (" HTTP/" + version + "\r\n").getBytes(StandardCharsets.UTF_8));

        for (Map.Entry<String, String> header : headers.entrySet()) {
            Util.addAll(bytes, (header.getKey() + ": " + header.getValue() + "\r\n").getBytes(StandardCharsets.UTF_8));
        }

        Util.addAll(bytes, "\r\n".getBytes(StandardCharsets.UTF_8));
        if (body != null && body.length > 0) {
            Util.addAll(bytes, body);
        }

        total = new byte[bytes.size()];
        for (int i = 0; i < total.length; i++) {
            total[i] = bytes.get(i);
        }
    }

    public byte[] getTotal() {
        if (total.length > 0)
            return total;
        toBytes();
        return total;
    }
}
