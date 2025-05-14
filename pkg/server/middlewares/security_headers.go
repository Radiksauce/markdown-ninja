package middlewares

import (
	"net/http"
	"strings"
)

func SetSecurityHeaders(next http.Handler) http.Handler {
	fn := func(res http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(res, req)

		// we only allow special routes to appear in an iframe, such as for video player
		if strings.HasPrefix(req.URL.Path, "__markdown_ninja") {
			res.Header().Del("X-Frame-Options")
		}
	}

	return http.HandlerFunc(fn)
}
