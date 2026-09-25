package imageproxy

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/valyala/fasthttp"
)

const (
	tokenURLParam = "token"
	noSniffHeader = "X-Content-Type-Options"
	cspHeader     = "Content-Security-Policy"
	svgCSP        = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
)

// Handler serves proxied images over HTTP via fasthttp.
// Token issuance is server-side only — there is no public POST endpoint.
type Handler struct {
	service *Service
}

// NewHandler creates a fasthttp handler backed by service.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// TokenURLParam is the router placeholder name used by Proxy.
// Example: r.GET("/images/proxy/{token}", handler.Proxy).
func (h *Handler) TokenURLParam() string {
	return tokenURLParam
}

// Proxy serves the image identified by the token router parameter.
func (h *Handler) Proxy(ctx *fasthttp.RequestCtx) {
	token, _ := ctx.UserValue(tokenURLParam).(string)
	if token == "" {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		return
	}

	image, err := h.service.Fetch(ctx, token)
	if err != nil {
		if !isClientError(err) {
			log.Println(fmt.Errorf("fetch image: %v", err))
		}
		writeServiceError(ctx, err)
		return
	}

	writeImage(ctx, image)
}

func writeImage(ctx *fasthttp.RequestCtx, image *Image) {
	header := &ctx.Response.Header
	header.Set(fasthttp.HeaderContentType, image.ContentType)
	header.Set(noSniffHeader, "nosniff")

	if image.CacheControl != "" {
		header.Set(fasthttp.HeaderCacheControl, image.CacheControl)
	}
	if image.ETag != "" {
		header.Set(fasthttp.HeaderETag, image.ETag)
	}
	if image.LastModified != "" {
		header.Set(fasthttp.HeaderLastModified, image.LastModified)
	}

	if image.IsSVG {
		header.Set(cspHeader, svgCSP)
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(image.Body)
}

func isClientError(err error) bool {
	switch {
	case errors.Is(err, ErrInvalidURL),
		errors.Is(err, ErrInvalidToken),
		errors.Is(err, ErrTokenNotFound):
		return true
	}

	return false
}

func writeServiceError(ctx *fasthttp.RequestCtx, err error) {
	upstreamStatus, ok := errors.AsType[*UpstreamStatusError](err)
	if ok && (upstreamStatus.StatusCode == fasthttp.StatusNotFound || upstreamStatus.StatusCode == fasthttp.StatusGone) {
		writeJSONError(ctx, upstreamStatus.StatusCode, "image_not_found")
		return
	}

	switch {
	case errors.Is(err, ErrInvalidURL):
		writeJSONError(ctx, fasthttp.StatusBadGateway, "upstream_unavailable")
	case errors.Is(err, ErrInvalidToken):
		writeJSONError(ctx, fasthttp.StatusBadRequest, "invalid_token")
	case errors.Is(err, ErrTokenNotFound):
		writeJSONError(ctx, fasthttp.StatusNotFound, "token_not_found")
	case errors.Is(err, ErrImageTooLarge):
		writeJSONError(ctx, fasthttp.StatusRequestEntityTooLarge, "image_too_large")
	case errors.Is(err, ErrUnsupportedContentType):
		writeJSONError(ctx, fasthttp.StatusBadGateway, "unsupported_content_type")
	case errors.Is(err, ErrStoreUnavailable):
		writeJSONError(ctx, fasthttp.StatusServiceUnavailable, "store_unavailable")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeJSONError(ctx, fasthttp.StatusGatewayTimeout, "upstream_timeout")
	case errors.Is(err, ErrRedirectDisallowed):
		writeJSONError(ctx, fasthttp.StatusBadGateway, "redirect_not_allowed")
	case errors.Is(err, ErrUpstreamUnavailable):
		writeJSONError(ctx, fasthttp.StatusBadGateway, "upstream_unavailable")
	default:
		writeJSONError(ctx, fasthttp.StatusInternalServerError, "internal_error")
	}
}

func writeJSONError(ctx *fasthttp.RequestCtx, status int, code string) {
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(status)
	//b, err := json.Marshal(map[string]string{"error": code})
	//if err != nil {
	//	ctx.SetBodyString(`{"error":"internal_error"}`)
	//	return
	//}
	//ctx.SetBody(b)
}
