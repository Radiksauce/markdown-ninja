package pingoo

import (
	"context"
	"log/slog"
	"net/http"

	"markdown.ninja/pingoo-go/rules"
)

type MiddlewareConfig struct {
	// serverless bool
	// geoip: local | http | cloudflare | disabled
	// rate limiting: memory | redis | (api | pingoo)
	// Rules
	// CdnProvider string
	Logging LoggingConfig
	Rules   []rules.Rule
}

type LoggingConfig struct {
	Disabled  bool
	GetLogger func(ctx context.Context) *slog.Logger
}

type MiddlewareOptionsHeaders struct {
}

func Middleware(config *MiddlewareConfig) func(next http.Handler) http.Handler {
	if config == nil {
		config = &MiddlewareConfig{}
	}
	return func(next http.Handler) http.Handler {
		fn := func(res http.ResponseWriter, req *http.Request) {

			// we need to apply the response rules BEFORE forwarding to the other middlewares / response
			// handlers because otherwise the headers and body may have been already sent
			// TODO: we may wrap res so that we apply the response rules when WriteHeader is called
			for _, rule := range config.Rules {
				if rule.Match == nil || (rule.Match != nil && rule.Match(req)) {
					for _, action := range rule.Actions {
						action.Apply(res, req)
					}
				}
			}

			next.ServeHTTP(res, req)

		}
		return http.HandlerFunc(fn)
	}
}
