package middlewares

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"markdown.ninja/pkg/server/apiutil"
)

// TODO: stack trace?
func Recoverer(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if recoverErr := recover(); recoverErr != nil {
				if recoverErr == http.ErrAbortHandler {
					// we don't recover http.ErrAbortHandler so the response
					// to the client is aborted, this should not be logged
					panic(recoverErr)
				}

				// TODO: find a better way to show the stack trace. Marshal to JSON for example.
				err := fmt.Errorf("middlewares.recover (%s): panic: %v\n %s", req.URL.Path, recoverErr, string(debug.Stack()))
				apiutil.SendError(req.Context(), w, err)
			}
		}()

		next.ServeHTTP(w, req)
	}

	return http.HandlerFunc(fn)
}
