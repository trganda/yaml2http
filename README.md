# Yaml2http

一个将`Xray`的`Poc`转换成`http`请求明文的小工具，便于在`Burp Suite`一类的工具中使用。与杜老师交流`Poc`存储问题而引出的产物，我们采用了一个简易版的基于`Xray`的`Poc`标准，它只支持描述`http`协议。目前功能尚不完善，还在开发中...

## Usage

运行

```bash
go run main -path <path_to_yaml_poc>
```

输出如下

```http
POST /index.jsp?c=898498081 HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36 Edg/104.0.1293.47
Connection: close
Accept: */*
Content-Length: 7
Content-Type: text/plain; charset=utf-8

a=b&b=a
```

## Todo

* [X] 完成`yaml`解析，读取已支持字段值
* [X] 完成变量定义外的`http`文本转换
* [X] 完成变量定义和表达式解析（已初步完成主体框架，后续补充方法功能即可）
* [X] 完成`Content-Type`自识别（但`body`数据过段会引起判断失误，推荐`poc`中自行指定）
* [ ] 完成变量定义字段其他方法的支持

