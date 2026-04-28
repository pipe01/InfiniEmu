package services

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dop251/goja"
)

type Options struct {
	Body    *string
	Headers map[string]string
}

type HttpService struct {
	VM *goja.Runtime
}

func (svc HttpService) Request(method string, url string, arg1 any, arg2 any) (any, error) {
	var options map[string]any
	var callback func(goja.FunctionCall) goja.Value

	if v, ok := arg1.(map[string]any); ok {
		options = v

		if f, ok := arg2.(func(goja.FunctionCall) goja.Value); ok {
			callback = f
		}
	} else if f, ok := arg1.(func(goja.FunctionCall) goja.Value); ok {
		callback = f
	}

	var body io.Reader
	if b := options["body"]; b != nil {
		body = strings.NewReader(b.(string))
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if h := options["headers"]; h != nil {
		for k, v := range h.(map[string]any) {
			req.Header.Set(k, fmt.Sprint(v))
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	respStr := string(respBody)

	if callback != nil {
		callback(goja.FunctionCall{
			Arguments: []goja.Value{
				svc.VM.ToValue(respStr),
			},
		})

		return nil, nil
	} else {
		return respStr, nil
	}
}
