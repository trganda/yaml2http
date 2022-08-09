package lib

import "errors"

const (
	MethodGet     = "GET"
	MethodHead    = "HEAD"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodPatch   = "PATCH" // RFC 5789
	MethodDelete  = "DELETE"
	MethodConnect = "CONNECT"
	MethodOptions = "OPTIONS"
	MethodTrace   = "TRACE"
)

const (
	Host       = "localhost"
	UserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36 Edg/104.0.1293.47"
	Connection = "close"
	Accept     = "*/*"
)

type HttpRequest struct {
	Method  string
	URI     string
	Version string
	Headers map[string]string
	Body    string
}

func ToHttpRequest(poc *Poc) (*[]HttpRequest, error) {
	if poc == nil {
		return nil, errors.New("Invalid Argument")
	}
	requests := &[]HttpRequest{}

	headers := make(map[string]string)
	headers["Host"] = Host
	headers["User-Agent"] = UserAgent
	headers["Connection"] = Connection
	headers["Accept"] = Accept

	for _, rule := range poc.Rules {
		request := HttpRequest{}
		req := rule.rule.Request
		request.Method = req.Method
		request.URI = req.Path
		request.Version = "1.1"
		request.Headers = headers
		for hkey, hvalue := range req.Headers {
			request.Headers[hkey] = hvalue
		}
		request.Body = req.Body
		*requests = append(*requests, request)
	}

	return requests, nil
}

func (req *HttpRequest) ToHttpRequestText() (string, error) {
	var ret string

	ret = req.Method + " " + req.URI + " " + "HTTP/" + req.Version + "\r\n"
	for hkey, hval := range req.Headers {
		ret = ret + hkey + ": " + hval + "\r\n"
	}
	ret = ret + "\r\n"

	return ret, nil
}
