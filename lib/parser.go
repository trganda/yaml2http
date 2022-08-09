package lib

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

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

	err := errors.New("invalid argument")
	if poc == nil {
		return nil, err
	}

	requests := &[]HttpRequest{}

	headers := make(map[string]string)
	headers["Host"] = Host
	headers["User-Agent"] = UserAgent
	headers["Connection"] = Connection
	headers["Accept"] = Accept

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	// Eval sets
	EvalSets(&poc.Set, variableMap)

	DealWithRule := func(rule RuleItem) HttpRequest {
		req := rule.Rule.Request

		for k, val := range variableMap {
			_, isMap := val.(map[string]string)
			if isMap {
				continue
			}

			val := fmt.Sprintf("%v", val)
			req.Path = strings.ReplaceAll(req.Path, "{{"+k+"}}", val)
			req.Body = strings.ReplaceAll(req.Body, "{{"+k+"}}", val)

			for headerName, headerVal := range req.Headers {
				if !strings.Contains(headerVal, "{{"+k+"}}") {
					continue
				}
				req.Headers[headerName] = strings.ReplaceAll(headerVal, "{{"+k+"}}", val)
			}
		}

		request := HttpRequest{}
		request.Method = req.Method
		request.URI = req.Path
		request.Version = "1.1"
		request.Headers = headers

		for hkey, hvalue := range req.Headers {
			request.Headers[hkey] = hvalue
		}

		request.Body = req.Body

		// Content-Length & Content-Type
		if request.Method == MethodPost {
			contentLength := fmt.Sprintf("%d", len(request.Body))
			request.Headers["Content-Length"] = contentLength
		}

		if request.Body != "" {
			buf := []byte(request.Body)
			contentType := GetContentType(buf)
			request.Headers["Content-Type"] = contentType
		}

		return request
	}

	DealWithRules := func(rules Rules) {
		for _, rule := range rules {
			request := DealWithRule(rule)
			*requests = append(*requests, request)
		}
	}

	DealWithRules(poc.Rules)

	return requests, nil
}

func GetContentType(buf []byte) string {
	ret := http.DetectContentType(buf)

	return ret
}

func (req *HttpRequest) ToHttpRequestText() (string, error) {
	var ret string

	ret = req.Method + " " + req.URI + " " + "HTTP/" + req.Version + "\r\n"
	for hkey, hval := range req.Headers {
		ret = ret + hkey + ": " + hval + "\r\n"
	}

	ret = ret + "\r\n"

	if req.Method == MethodPost {
		ret = ret + req.Body
	}

	return ret, nil
}
