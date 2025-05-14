package apiutil

import (
	"net/http"

	"markdown.ninja/pkg/errs"
)

func NotFoundHandler(w http.ResponseWriter, req *http.Request) {
	err := errs.NotFound("Route not found.")
	SendError(req.Context(), w, err)
}

func IndexHandler(w http.ResponseWriter, req *http.Request) {
	res := map[string]string{"hello": "Markdown Ninja"}
	SendResponse(req.Context(), w, http.StatusOK, res)
}

func InternalErrorhandler(w http.ResponseWriter, req *http.Request) {
	err := errs.Internal("Internal error", nil)
	SendError(req.Context(), w, err)
}
