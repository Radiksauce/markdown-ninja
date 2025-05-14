package server

import "time"

// See https://blog.cloudflare.com/exposing-go-on-the-internet for more information about timeouts
// and https://developers.cloudflare.com/load-balancing/understand-basics/load-balancers
const (
	// readHeaderTimeout is the ReadHeaderTimeout of the `http.Server`
	readHeaderTimeout = 5 * time.Second
	// readTimeout is the ReadTimeout of the `http.Server`
	// we put as a higher value for uploads
	readTimeout = 5 * time.Minute
	// writeTimeout is the WriteTimeout of the `http.Server`
	// we currently disable this as it's making too many problems with downloads
	writeTimeout = 15 * time.Minute
	// idleTimeout is the IdleTimeout of the `http.Server`
	idleTimeout    = 5 * time.Minute
	idleTimeoutCdn = 30 * time.Minute

	http2ReadIdleTimeout = 30 * time.Second

	// the number of seconds that requests have to complete once the server shutdown is initiated
	// if you use some PaaS, they have a maximum shutdown time allowed, such as render.com: 30 seconds
	shutdownTimeout = 25 * time.Second

	requestIDHeader = "X-Request-ID"
)
