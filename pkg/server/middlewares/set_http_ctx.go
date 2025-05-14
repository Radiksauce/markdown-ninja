package middlewares

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/bloom42/stdx-go/countries"
	"github.com/bloom42/stdx-go/httpx"
	"github.com/bloom42/stdx-go/log/slogx"
	"github.com/bloom42/stdx-go/uuid"
	"markdown.ninja/pkg/geoip"
	"markdown.ninja/pkg/server/httpctx"
)

// type gizmoClientMetadataHeader struct {
// 	HttpVersion int    `json:"http_version"`
// 	RemotePort  uint16 `json:"remote_port"`
// 	Port        uint16 `json:"port"`
// 	IPStr       string `json:"ip"`
// 	IPVersion   int    `json:"ip_version"`
// 	ASN         uint64 `json:"asn"`
// 	ASName      string `json:"as_name"`
// 	CountryCode string `json:"country"`
// 	UseTor      bool   `json:"tor"`
// }

// SetHTTPContext injects `httpctx.Context` in requests' context
func SetHTTPContext(geoipResolver *geoip.Resolver) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, req *http.Request) {
			var err error

			ctx := req.Context()
			logger := slogx.FromCtx(ctx)

			httpCtx := httpctx.Context{
				Client: httpctx.ClientData{},
				Response: httpctx.Response{
					Headers:  make(http.Header),
					Cookies:  make([]http.Cookie, 0, 2),
					CacheHit: nil,
				},
				Request: httpctx.Request{
					IfNoneMatch: nil,
				},
			}
			httpCtx.RequestID = ctx.Value(RequestIDCtxKey).(uuid.UUID)
			httpCtx.Headers = req.Header
			httpCtx.Url = req.URL

			httpCtx.Hostname = req.Host
			httpCtx.Client.UserAgent = strings.TrimSpace(req.UserAgent())

			// IP address
			httpCtx.Client.IPStr, httpCtx.Client.IP, err = extractClientIpAddress(req)
			if err != nil {
				logger.Error(err.Error())
				httpx.ServerErrorInternal(w)
				return
			}
			// Country and ASN
			httpCtx.Client.CountryCode, httpCtx.Client.ASN, err =
				getCountryCodeAndAsnFromClientIP(logger, geoipResolver, httpCtx.Client.IP)
			if err != nil {
				httpx.ServerErrorInternal(w)
				return
			}
			httpCtx.Client.ASNStr = strconv.FormatInt(httpCtx.Client.ASN, 10)

			httpCtx.CfRayID = strings.TrimSpace(req.Header.Get("CF-ray"))

			ifNoneMatchHeader := strings.TrimSpace(req.Header.Get(httpx.HeaderIfNoneMatch))
			if ifNoneMatchHeader != "" {
				ifNoneMatchHeader = strings.TrimPrefix(ifNoneMatchHeader, "W/")
				ifNoneMatchHeader = strings.Trim(ifNoneMatchHeader, `"`)
				httpCtx.Request.IfNoneMatch = &ifNoneMatchHeader
			}

			ctx = context.WithValue(ctx, httpctx.CtxKey, &httpCtx)

			// we don't want to set the client IP to avoid being easily fingerprintable
			// w.Header().Set("X-Client-Ip", httpCtx.Client.IPStr)

			next.ServeHTTP(w, req.WithContext(ctx))
		}

		return http.HandlerFunc(fn)
	}
}

func getCountryCodeAndAsnFromClientIP(logger *slog.Logger, geoipResolver *geoip.Resolver, clientIP netip.Addr) (countryCode string, asn int64, err error) {
	geoipInfo, err := geoipResolver.Lookup(clientIP)
	if err != nil {
		err = fmt.Errorf("middleware.SetHTTPContext: error looking up for geoIP information for IP address: %s", clientIP)
		return
	}

	asn = geoipInfo.ASN
	countryCode = geoipInfo.Country

	// sometimes the country code can be invalid
	_, errCountryName := countries.Name(countryCode)
	if errors.Is(errCountryName, countries.ErrCountryNotFound) {
		if countryCode != "" && countryCode != countries.CodeUnknown {
			logger.Warn("middleware.SetHTTPContext: Country not found", slog.String("country_code", countryCode))
		}
		countryCode = countries.CodeUnknown
	}

	return
}

func extractClientIpAddress(req *http.Request) (clientIpStr string, clientIp netip.Addr, err error) {
	clientIpStr, _, err = net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		err = fmt.Errorf("middleware.extractClientIpAddress: RemoteAddr (%s) is not valid: %w", clientIpStr, err)
		return
	}

	clientIp, err = netip.ParseAddr(clientIpStr)
	if err != nil {
		err = fmt.Errorf("middleware.extractClientIpAddress: error parsing client IP [%s]: %w", clientIpStr, err)
		return
	}

	return
}
