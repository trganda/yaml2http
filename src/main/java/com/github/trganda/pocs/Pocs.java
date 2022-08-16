package com.github.trganda.pocs;

/**
 * name: poc-yaml-example-com
 * transport: http
 * set:
 *     r1: randomInt(800000000, 1000000000)
 *     r2: randomInt(800000000, 1000000000)
 *     r3: base64(b'asdf')
 * rules:
 *     r1:
 *         request:
 *             method: POST
 *             path: "/index.jsp?c={{r3}}"
 *             body: "a=b&b=a"
 *         expression: |
 *             response.status==200 && response.body.bcontains(b'Example Domain')
 * expression: |
 *     r1()
 * detail:
 *     author: name(link)
 *     links:
 *         - http://example.com
 */
public class Pocs {
    public String name;
    public String transport;
    public String expression;
    public Sets set;
    public Rules rules;
    public Detail detail;

    public Pocs() {

    }

    public Pocs(String name, String transport, String expression, Detail detail) {
        this.name = name;
        this.transport = transport;
        this.expression = expression;
        this.detail = detail;
    }

    @Override
    public String toString() {
        return "Pocs{" +
                "name='" + name + '\'' +
                ", transport='" + transport + '\'' +
                ", expression='" + expression + '\'' +
                ", set=" + set +
                ", rules=" + rules +
                ", detail=" + detail +
                '}';
    }
}
