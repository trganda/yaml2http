package com.github.trganda.parser;

import com.github.trganda.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * type HttpRequest struct {
 * 	Method  string
 * 	URI     byte[]
 * 	Version string
 * 	Headers map[string]string
 * 	Body    byte[]
 * }
 */
public final class HttpRequest {

    public final static Map<String, byte[]> defaultHeader =
            Stream.of(
                    new AbstractMap.SimpleEntry<>("Host", "localhost".getBytes(StandardCharsets.UTF_8)),
                    new AbstractMap.SimpleEntry<>("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36 Edg/104.0.1293.47".getBytes(StandardCharsets.UTF_8)),
                    new AbstractMap.SimpleEntry<>("Connection", "close".getBytes(StandardCharsets.UTF_8)),
                    new AbstractMap.SimpleEntry<>("Accept", "*/*".getBytes(StandardCharsets.UTF_8))).
                    collect(Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue));

    private final String method;
    private final byte[] uri;
    private final String version;
    private final Map<String, byte[]> headers;
    private final byte[] body;
    private byte[] total;

    public HttpRequest(String method, byte[] uri,
                       String version, Map<String, byte[]> headers, byte[] body) {
        this.method = method;
        this.uri = uri;
        this.version = version;
        this.headers = headers;
        this.body = body;
        total = new byte[0];
        init();
    }

    private void init() {
        if (total.length == 0) {
            try {
                toBytes();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public String toString() {
        return new String(total, StandardCharsets.UTF_8);
    }

    private void toBytes() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        buf.write((method + " ").getBytes(StandardCharsets.UTF_8));
        buf.write(uri);
        buf.write((" HTTP/" + version + "\r\n").getBytes(StandardCharsets.UTF_8));

        for (Map.Entry<String, byte[]> header : headers.entrySet()) {
            buf.write((header.getKey() + ": ").getBytes(StandardCharsets.UTF_8));
            buf.write(header.getValue());
            buf.write("\r\n".getBytes(StandardCharsets.UTF_8));
        }

        buf.write("\r\n".getBytes(StandardCharsets.UTF_8));
        if (body != null && body.length > 0) {
            buf.write(body);
        }

        total = buf.toByteArray();
    }

    public byte[] getTotal() {
        return total;
    }
}
