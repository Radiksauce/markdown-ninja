package middlewares

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Redirects middleware redirects request in the following situations:
// - from www.(primaryDomain|websitesRootDomain) to (primaryDomain|websitesRootDomain)
// - from websitesRootDomain to primaryDomain if websitesRootDomain != primaryDomain
func Redirects(primaryDomain, websitesRootDomain string) func(next http.Handler) http.Handler {
	wwwPrimaryDomain := fmt.Sprintf("www.%s", primaryDomain)
	wwwWebsitesRootDomain := fmt.Sprintf("www.%s", websitesRootDomain)
	primaryDomainIsSameAsWebsitesRootDomain := primaryDomain == websitesRootDomain
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, req *http.Request) {
			if req.Host == wwwPrimaryDomain || req.Host == wwwWebsitesRootDomain {
				to := generateRedirectUrl(req.URL, stripWwwSubdomain(req.Host))
				http.Redirect(w, req, to, http.StatusMovedPermanently)
				return
			} else if req.Host == websitesRootDomain && !primaryDomainIsSameAsWebsitesRootDomain {
				to := generateRedirectUrl(req.URL, primaryDomain)
				http.Redirect(w, req, to, http.StatusMovedPermanently)
				return
			}

			next.ServeHTTP(w, req)
		}

		return http.HandlerFunc(fn)
	}
}

func stripWwwSubdomain(host string) string {
	if strings.Count(host, ".") > 1 {
		return strings.TrimPrefix(host, "www.")
	}
	return host
}

func generateRedirectUrl(reqUrl *url.URL, toHost string) string {
	to := url.URL{
		Scheme:   "https",
		Host:     toHost,
		Path:     reqUrl.Path,
		RawQuery: reqUrl.RawQuery,
	}
	return to.String()
}
