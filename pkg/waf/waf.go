package waf

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bloom42/stdx-go/httpx"
	"github.com/bloom42/stdx-go/log/slogx"
	"github.com/bloom42/stdx-go/memorycache"
	"github.com/bloom42/stdx-go/retry"
	"github.com/bloom42/stdx-go/set"
	"github.com/tetratelabs/wazero"
	wazeroapi "github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"markdown.ninja/assets"
	"markdown.ninja/pkg/server/httpctx"
)

type Waf struct {
	blockedCountries set.Set[string]
	logger           *slog.Logger
	dnsResolver      *net.Resolver

	wasmRuntime        wazero.Runtime
	compiledWasmModule wazero.CompiledModule
	wasmModulePool     *sync.Pool

	allowedBotIps *memorycache.Cache[netip.Addr, bool]
}

type wasmModule struct {
	module         wazeroapi.Module
	analyzeRequest wazeroapi.Function
	verifyBot      wazeroapi.Function
	allocate       wazeroapi.Function
	deallocate     wazeroapi.Function
}

var dnsServers = []string{
	"8.8.8.8:53",
	"1.0.0.1:53",
	"8.8.4.4:53",
	"1.1.1.1:53",
	// "9.9.9.9:53",
}

type analyzeRequestInput struct {
	HttpMethod       string     `json:"http_method"`
	UserAgent        string     `json:"user_agent"`
	IpAddress        netip.Addr `json:"ip_address"`
	Asn              int64      `json:"asn"`
	Path             string     `json:"path"`
	HttpVersionMajor int64      `json:"http_version_major"`
	HttpVersionMinor int64      `json:"http_version_minor"`
}

type verifyBotInput struct {
	Bot               int64      `json:"bot"`
	IpAddress         netip.Addr `json:"ip_address"`
	Asn               int64      `json:"asn"`
	IpAddressHostname string     `json:"ip_address_hostname"`
}

type outcome string

const (
	outcomeAllowed outcome = "allowed"
	outcomeBlocked outcome = "blocked"
	outcomeBot     outcome = "bot"
)

type analyzeRequestOutputData struct {
	Outcome outcome `json:"outcome"`
	Bot     int64   `json:"bot"`
}

type analyzeRequestOutput struct {
	Data *analyzeRequestOutputData `json:"data"`
	Err  *string                   `json:"err"`
}

func New(blockedCountries set.Set[string], logger *slog.Logger) (waf *Waf, err error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	allowedBotIps := memorycache.New(
		memorycache.WithTTL[netip.Addr, bool](7*24*time.Hour), // 7 days
		memorycache.WithCapacity[netip.Addr, bool](20_000),
	)

	wasmCtx := context.Background()
	// wasmCtx = experimental.WithMemoryAllocator(wasmCtx, wazeroallocator.NewNonMoving())

	// See https://github.com/tetratelabs/wazero/issues/2156
	// and https://github.com/wasilibs/go-re2/blob/main/internal/re2_wazero.go
	// for imformation about how to configure wazero to use a WASM lib using WASM memory

	// More wazero docs:
	// How to use HostFunctionBuilder with multiple goroutines? https://github.com/tetratelabs/wazero/issues/2217
	// Clarification on concurrency semantics for invocations https://github.com/tetratelabs/wazero/issues/2292
	// Improve InstantiateModule concurrency performance https://github.com/tetratelabs/wazero/issues/602
	// Add option to change Memory capacity https://github.com/tetratelabs/wazero/issues/500
	// Document best practices around invoking a wasi module multiple times https://github.com/tetratelabs/wazero/issues/985
	// API shape https://github.com/tetratelabs/wazero/issues/425

	wasmRuntime := wazero.NewRuntimeWithConfig(wasmCtx, wazero.NewRuntimeConfigCompiler().WithCoreFeatures(wazeroapi.CoreFeaturesV2|experimental.CoreFeaturesThreads).WithMemoryLimitPages(65536).WithDebugInfoEnabled(true))

	wasi_snapshot_preview1.MustInstantiate(wasmCtx, wasmRuntime)

	// _, err = wasmRuntime.InstantiateWithConfig(wasmCtx, assets.MemoryWasm, wazero.NewModuleConfig().WithName("env"))
	// if err != nil {
	// 	return nil, fmt.Errorf("waf: error instantiating wasm memory module: %w", err)
	// }

	// _, err = wasmRuntime.NewHostModuleBuilder("host").
	// 	NewFunctionBuilder().WithFunc(waf.wasmLog).Export("log").
	// 	Instantiate(wasmCtx)
	// if err != nil {
	// 	return nil, fmt.Errorf("waf: error instantiating wasm host module: %w", err)
	// }

	compiledWasmModule, err := wasmRuntime.CompileModule(wasmCtx, assets.PingooWasm)
	if err != nil {
		return nil, fmt.Errorf("waf: error compiling wasm pingoo module: %w", err)
	}

	// as recommended in https://github.com/tetratelabs/wazero/issues/2217
	// we use a sync.Pool of wasm modules in order to handle concurrency
	wasmPool := &sync.Pool{
		New: func() any {
			poolObjectCtx := context.Background()
			instantiatedWasmModule, err := wasmRuntime.InstantiateModule(poolObjectCtx, compiledWasmModule, wazero.NewModuleConfig().
				WithStartFunctions("_initialize").WithSysNanosleep().WithSysNanotime().WithSysWalltime().WithName("").WithRandSource(cryptorand.Reader),
			// for debugging
			// .WithStdout(os.Stdout).WithStderr(os.Stderr),
			)
			if err != nil {
				logger.Error("waf.wasmModulePool.New: error instantiating WASM module", slogx.Err(err))
				return nil
			}

			poolObject := &wasmModule{
				module:         instantiatedWasmModule,
				analyzeRequest: instantiatedWasmModule.ExportedFunction("analyze_request"),
				verifyBot:      instantiatedWasmModule.ExportedFunction("verify_bot"),
				allocate:       instantiatedWasmModule.ExportedFunction("allocate"),
				deallocate:     instantiatedWasmModule.ExportedFunction("deallocate"),
			}
			// use a finalizer to Close the module, as recommended in https://github.com/golang/go/issues/23216
			runtime.SetFinalizer(poolObject, func(object *wasmModule) {
				object.module.Close(poolObjectCtx)
			})
			return poolObject
		},
	}

	dnsResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: 5 * time.Second,
			}
			dnsServer := dnsServers[rand.IntN(len(dnsServers))]
			return dialer.DialContext(ctx, network, dnsServer)
		},
	}

	waf = &Waf{
		blockedCountries: blockedCountries,
		logger:           logger,
		allowedBotIps:    allowedBotIps,
		dnsResolver:      dnsResolver,

		wasmRuntime:        wasmRuntime,
		compiledWasmModule: compiledWasmModule,
		wasmModulePool:     wasmPool,
	}

	return
}

func (waf *Waf) Middleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		userAgent := req.UserAgent()
		var err error
		path := req.URL.Path

		ctx := req.Context()
		httpCtx := httpctx.FromCtx(ctx)

		if len(userAgent) == 0 || len(userAgent) > 300 || !utf8.ValidString(userAgent) ||
			len(path) > 1024 || !utf8.ValidString(path) ||
			len(req.Method) > 20 ||
			waf.blockedCountries.Contains(httpCtx.Client.CountryCode) {
			waf.serveBlockedResponse(w)
			return
		}

		wasmModulePoolObject := waf.wasmModulePool.Get()
		if wasmModulePoolObject == nil {
			// fail open
			waf.logger.Error("waf: Error getting object from wasm sync.Pool. Object is nil")
			next.ServeHTTP(w, req)
			return
		}

		wasmModule := wasmModulePoolObject.(*wasmModule)
		defer waf.wasmModulePool.Put(wasmModule)

		analyzeRequestAllowed, err := waf.analyzeRequest(req, wasmModule)
		if err != nil {
			// fail open
			waf.logger.Error(err.Error(), slog.String("user_agent", userAgent),
				slog.String("ip_address", httpCtx.Client.IP.String()), slog.Int64("asn", httpCtx.Client.ASN))
			next.ServeHTTP(w, req)
			return
		}
		if !analyzeRequestAllowed {
			waf.serveBlockedResponse(w)
			return
		}

		next.ServeHTTP(w, req)
	}

	return http.HandlerFunc(fn)
}

// return true if allowed, false otherwise
func (waf *Waf) analyzeRequest(req *http.Request, wasmModule *wasmModule) (bool, error) {
	ctx := req.Context()
	httpCtx := httpctx.FromCtx(ctx)
	logger := slogx.FromCtx(ctx)

	wasmCtx := context.Background()

	analyzeRequestInput := analyzeRequestInput{
		HttpMethod:       req.Method,
		UserAgent:        req.UserAgent(),
		IpAddress:        httpCtx.Client.IP,
		Asn:              httpCtx.Client.ASN,
		Path:             req.URL.Path,
		HttpVersionMajor: int64(req.ProtoMajor),
		HttpVersionMinor: int64(req.ProtoMinor),
	}
	analyzeRequestInputWasmPtr, analyzeRequestInputWasmLength, err := serializeJsonToWasm(wasmCtx, wasmModule.module, wasmModule.allocate, analyzeRequestInput)
	if err != nil {
		return false, fmt.Errorf("waf.analyzeRequest: serializing input for analyze_request call %w", err)
	}
	defer func() {
		// This pointer was allocated by Rust so we have to deallocate it when finished
		_, deallocateErr := wasmModule.deallocate.Call(wasmCtx, analyzeRequestInputWasmPtr, analyzeRequestInputWasmLength)
		if deallocateErr != nil {
			logger.Error("waf.analyzeRequest: error deallocating wasm input memory for analyze_request function call", slogx.Err(deallocateErr))
		}
	}()

	wasmResultsAnalyzeRequest, err := wasmModule.analyzeRequest.Call(wasmCtx, analyzeRequestInputWasmPtr, analyzeRequestInputWasmLength)
	if err != nil {
		return false, fmt.Errorf("waf.analyzeRequest: error calling wasm function analyze_request: %w", err)
	}

	analyzeRequestOutputPtr := uint32(wasmResultsAnalyzeRequest[0] >> 32)
	analyzeRequestOutputSize := uint32(wasmResultsAnalyzeRequest[0])

	analyzeRequestRes, err := deserializeJsonFromWasm[analyzeRequestOutput](wasmModule.module, analyzeRequestOutputPtr, analyzeRequestOutputSize)
	if err != nil {
		return false, fmt.Errorf("waf.analyzeRequest: error unmarshalling JSON output: %w", err)
	}
	// This pointer was allocated by Rust so we have to deallocate it when finished
	_, err = wasmModule.deallocate.Call(ctx, uint64(analyzeRequestOutputPtr), uint64(analyzeRequestOutputSize))
	if err != nil {
		logger.Error("waf.analyzeRequest: error deallocating wasm output memory", slogx.Err(err))
		err = nil
	}

	if analyzeRequestRes.Err != nil {
		return false, fmt.Errorf("waf.analyzeRequest: error analyzing request: %s", *analyzeRequestRes.Err)
	}

	if analyzeRequestRes.Data.Outcome == outcomeAllowed {
		return true, nil
	} else if analyzeRequestRes.Data.Outcome == outcomeBlocked {
		return false, nil
	} else if analyzeRequestRes.Data.Outcome == outcomeBot {
		if waf.allowedBotIps.Has(httpCtx.Client.IP) {
			return true, nil
		}

		hostnameForIpAddress, _ := waf.resolveHostForIp(ctx, httpCtx.Client.IP)
		verifyBotInput := verifyBotInput{
			IpAddress:         httpCtx.Client.IP,
			Asn:               httpCtx.Client.ASN,
			Bot:               analyzeRequestRes.Data.Bot,
			IpAddressHostname: hostnameForIpAddress,
		}
		verifyBotInputWasmPtr, verifyBotInputWasmLength, err := serializeJsonToWasm(wasmCtx, wasmModule.module, wasmModule.allocate, verifyBotInput)
		if err != nil {
			return false, fmt.Errorf("waf.analyzeRequest: serializing input for verify_bot call %w", err)
		}
		defer func() {
			// This pointer was allocated by Rust so we have to deallocate it when finished
			_, deallocateErr := wasmModule.deallocate.Call(wasmCtx, verifyBotInputWasmPtr, verifyBotInputWasmLength)
			if deallocateErr != nil {
				logger.Error("waf.analyzeRequest: error deallocating wasm input memory for verify_bot function call", slogx.Err(deallocateErr))
			}
		}()

		wasmResultsVerifyBot, err := wasmModule.verifyBot.Call(wasmCtx, verifyBotInputWasmPtr, verifyBotInputWasmLength)
		if err != nil {
			return false, fmt.Errorf("waf.analyzeRequest: error calling wasm function verify_bot: %w", err)
		}

		verifyBotOutputPtr := uint32(wasmResultsVerifyBot[0] >> 32)
		verifyBotOutputSize := uint32(wasmResultsVerifyBot[0])

		verifyBotRes, err := deserializeJsonFromWasm[analyzeRequestOutput](wasmModule.module, verifyBotOutputPtr, verifyBotOutputSize)
		if err != nil {
			return false, fmt.Errorf("waf.analyzeRequest: error unmarshalling JSON output for verify_bot function call: %w", err)
		}
		// This pointer was allocated by Rust so we have to deallocate it when finished
		_, err = wasmModule.deallocate.Call(ctx, uint64(verifyBotOutputPtr), uint64(verifyBotOutputSize))
		if err != nil {
			logger.Error("waf.analyzeRequest: error deallocating wasm output memory for verify_bot function call", slogx.Err(err))
			err = nil
		}

		if verifyBotRes.Err != nil {
			return false, fmt.Errorf("waf.analyzeRequest: error verifying bot: %s", *verifyBotRes.Err)
		}

		if verifyBotRes.Data.Outcome == outcomeAllowed {
			waf.allowedBotIps.Set(httpCtx.Client.IP, true, memorycache.DefaultTTL)
			return true, nil
		} else {
			return false, nil
		}
	}

	return true, nil
}

func serializeJsonToWasm[T any](wasmCtx context.Context, wasmModule wazeroapi.Module, wasmFnAllocate wazeroapi.Function, data T) (wasmDataPtr uint64, wasmDataLength uint64, err error) {
	dataJson, err := json.Marshal(data)
	if err != nil {
		return 0, 0, fmt.Errorf("waf.serializeJsonToWasm: error marshalling data to JSON: %w", err)
	}
	wasmDataLength = uint64(len(dataJson))

	allocateResults, err := wasmFnAllocate.Call(wasmCtx, wasmDataLength)
	if err != nil {
		return 0, 0, fmt.Errorf("waf.serializeJsonToWasm: error allocating memory: %w", err)
	}

	wasmDataPtr = allocateResults[0]

	// The pointer is a linear memory offset, which is where we write the data
	if !wasmModule.Memory().Write(uint32(wasmDataPtr), dataJson) {
		return 0, 0, fmt.Errorf("waf.analyzeRequest: Memory.Write(%d, %d) out of range of memory size %d", wasmDataPtr, wasmDataLength, wasmModule.Memory().Size())
	}

	return wasmDataPtr, wasmDataLength, nil
}

func deserializeJsonFromWasm[T any](wasmModule wazeroapi.Module, dataPtr, dataSize uint32) (T, error) {
	var data T

	// The pointer is a linear memory offset, which is where we wrote the data.
	dataBytes, memoryReadOk := wasmModule.Memory().Read(dataPtr, dataSize)
	if !memoryReadOk {
		return data, fmt.Errorf("waf.deserializeJsonFromWasm: error reading output: Memory.Read(%d, %d) out of range of memory size %d",
			dataPtr, dataSize, wasmModule.Memory().Size())
	}

	err := json.Unmarshal(dataBytes, &data)
	if err != nil {
		return data, fmt.Errorf("waf.deserializeJsonFromWasm: error unmarshalling JSON output: %w", err)
	}

	return data, nil
}

func (waf *Waf) serveBlockedResponse(res http.ResponseWriter) {
	sleepForMs := rand.Int64N(500) + 1000
	time.Sleep(time.Duration(sleepForMs) * time.Millisecond)

	message := "Access denied\n"

	res.Header().Set(httpx.HeaderConnection, "close")
	res.Header().Del(httpx.HeaderETag)
	res.Header().Set(httpx.HeaderCacheControl, httpx.CacheControlNoCache)
	res.Header().Set(httpx.HeaderContentType, httpx.MediaTypeTextUtf8)
	res.Header().Set(httpx.HeaderContentLength, strconv.FormatInt(int64(len(message)), 10))
	res.WriteHeader(http.StatusForbidden)
	res.Write([]byte(message))
}

// func (waf *Waf) wasmLog(ctx context.Context, wasmModule wazeroapi.Module, offset, byteCount uint32) {
// 	buffer, ok := wasmModule.Memory().Read(offset, byteCount)
// 	if !ok {
// 		return
// 	}
// 	waf.logger.Info(fmt.Sprintf("[WASM] %s", string(buffer)))
// }

func (waf *Waf) resolveHostForIp(ctx context.Context, ip netip.Addr) (string, error) {
	var hosts []string
	err := retry.Do(func() (retryErr error) {
		hosts, retryErr = waf.dnsResolver.LookupAddr(ctx, ip.String())
		if retryErr != nil {
			return retryErr
		}

		return nil
	}, retry.Context(ctx), retry.Attempts(3), retry.Delay(50*time.Millisecond))
	if err != nil {
		return "", fmt.Errorf("waf: error resolving hosts for IP address (%s): %w", ip, err)
	}

	cleanedUpHosts := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSuffix(strings.TrimSpace(host), ".")
		if host != "" {
			cleanedUpHosts = append(cleanedUpHosts, host)
		}
	}
	hosts = cleanedUpHosts

	if len(hosts) > 0 {
		return hosts[0], nil
	}

	return "", nil
}
