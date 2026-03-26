package services

import (
	"io"
	"net/http"
	"strings"
)

type Options struct {
	Body    *string
	Headers map[string]string
}

type HttpService struct{}

func (HttpService) Request(method string, url string, options Options) {
	var body io.Reader
	if options.Body != nil {
		body = strings.NewReader(*options.Body)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return
	}

	if options.Headers != nil {
		for k, v := range options.Headers {
			req.Header.Set(k, v)
		}
	}

	_, err = http.DefaultClient.Do(req)
	if err != nil {
		return
	}
}
