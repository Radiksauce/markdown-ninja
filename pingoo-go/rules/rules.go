package rules

import (
	"net/http"
)

type Rule struct {
	Match   func(req *http.Request) bool
	Actions []Action
}

type Action interface {
	RuleID() string
	Apply(res http.ResponseWriter, req *http.Request)
}

type HttpHeader struct {
	Name  string
	Value string
}

type ActionSkipAuth struct{}

func (ActionSkipAuth) RuleID() string {
	return "skip_auth"
}

func (action ActionSkipAuth) Apply(res http.ResponseWriter, req *http.Request) {}

type ActionSetRequestHeader struct {
	Headers []HttpHeader
}

func (ActionSetRequestHeader) RuleID() string {
	return "set_request_header"
}

func (action ActionSetRequestHeader) Apply(res http.ResponseWriter, req *http.Request) {
	for _, header := range action.Headers {
		req.Header.Set(header.Name, header.Value)
	}
}

type ActionSetResponseHeader struct {
	Headers []HttpHeader
}

func (ActionSetResponseHeader) RuleID() string {
	return "set_response_header"
}

func (action ActionSetResponseHeader) Apply(res http.ResponseWriter, req *http.Request) {
	for _, header := range action.Headers {
		res.Header().Set(header.Name, header.Value)
	}
}

type ActionRemoveResponseHeader struct {
	Headers []string
}

func (ActionRemoveResponseHeader) RuleID() string {
	return "remove_response_header"
}

func (action ActionRemoveResponseHeader) Apply(res http.ResponseWriter, req *http.Request) {
	resHeaders := res.Header()
	for _, headerName := range action.Headers {
		resHeaders.Del(headerName)
	}
}
