整体格式参考[Xray](https://docs.xray.cool/#/guide/poc/v2)，简化版本。

### 示例

如下是一个`poc`示例：
```yaml
name: poc-yaml-example-com
# 脚本部分
transport: http
rules:
    r1:
        request:
            method: GET
            path: "/"
        expression: |
            response.status==200 && response.body.bcontains(b'Example Domain')
expression:
    r1()
# 信息部分
detail:
    author: name(link)
    links: 
        - http://example.com

```
整个`poc`分为`3`个部分

- 名称部分：`poc`名称，类型为`string`
- 脚本逻辑部分：`poc`规则，描述`poc`的主要构成
- 描述信息部分：其它描述

### 脚本部分

分为`4`个部分

- 传输协议，仅支持`http`
- 变量定义（`set`）
- 规则描述（`rules`）
- 规则表达式（`expression`）

#### 传输协议

用于指定所用协议，只支持http。`transport: http`

#### 变量定义

可定义在规则或表达式中需要使用的变量，例如字符串或随机数，格式如下
```yaml
set:
    a: 1
```

#### 规则描述

定义具体规则`rules`
```yaml
rules:
    # 规则可以有多个，r0 r1 r2...
    r1:
        # 此处为一个 http request 的例子
        request:
            method: GET
            path: "/"
        expression: |
            response.status==200 && response.body.bcontains(b'Example Domain')
```
每一个`rule`包含以下内容

- 唯一的`key`值，如`r1`
- `request`：用于构造请求，也就是`poc`
- `expression`：用于判断返回结果，检查响应内容

`request`完整支持的字段如下
```yaml
# 请求方法
method: GET
# URI，可携带参数
path: /
# 请求头字段
headers:
    Content-Type: application/xml
# 请求体内容
body: aaaa
```
`expression`用于检查`poc`的执行结果
```yaml
expression: |
    response.status==200 && response.body.bcontains(b'Example Domain')
```

#### 规则表达式

规则表达式也以`expression`为标记，`expression: string`。
定义规则间的执行逻辑，如
```yaml
expression: |
    r1() || r2()
```

### Expression编写

`expression`使用[Common Expression Language (CEL)](https://github.com/google/cel-spec)表达式语法，类似于`spel`或`ognl`，用于在`golang`中执行语句。

除了`cel`自带的函数，当前还支持以下函数

#### 字符串处理

| **函数名** | **函数原型** | **说明** |
|---------| --- | --- |
| substr | func substr(string, start int, length int) string | 截取字符串 |

#### 编码加密函数

| **函数名** | **函数原型** | **说明** |
|---------| --- |----------------------------|
| md5 | func md5(string) string	| 字符串的 md5                   |
| base64 | func base64(string/bytes) string | 将字符串或 bytes 进行 base64 编码   |
| base64Decode | func base64Decode(string/bytes) string | 将字符串或 bytes 进行 base64 解码   |
| urlencode | func urlencode(string/bytes) string | 将字符串或 bytes 进行 urlencode 编码 |
| urldecode | func urldecode(string/bytes) string | 将字符串或 bytes 进行 urldecode 解码 |