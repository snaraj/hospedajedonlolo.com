package server

import (
	"regexp"
	"time"
)

const (
	indexName    = "index.html"
	assetsPrefix = "assets/"

	// forwardedProtoHeader is set by the tunnel connector from the edge's
	// view of the visitor's scheme. Only the exact lowercase values matter.
	forwardedProtoHeader = "X-Forwarded-Proto"

	// contentSecurityPolicy is the whole browser policy for the page. Keep it
	// in lockstep with server_test.go's pinned copy and compliance.json.
	contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; " +
		"img-src 'self' data:; font-src 'self'; media-src 'self'; " +
		"frame-src https://maps.google.com https://www.google.com; " +
		"base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"

	// mediaContentSecurityPolicy replaces the page policy on media responses:
	// a photograph opened directly can run nothing and embed nothing.
	mediaContentSecurityPolicy = "default-src 'none'; sandbox"

	// pageCacheControl makes every visit revalidate the page, stylesheet and
	// script by ETag, so a release reaches visitors on their next load.
	pageCacheControl = "no-cache"
	// assetCacheControl lets the edge and browsers keep fonts and media for a
	// day; the strong SHA-256 ETag makes the revalidation after that a 304.
	assetCacheControl = "public, max-age=86400"

	// writeIdleTimeout is the longest a response may stall between writes.
	writeIdleTimeout = 30 * time.Second

	// MaxMediaConcurrency is the ceiling an operator may configure.
	MaxMediaConcurrency = 256
	maxRangeHeaderBytes = 4096
	maxRangeParts       = 16

	requestIDHeader         = "X-Request-Id"
	traceparentHeader       = "traceparent"
	generatedRequestIDBytes = 16
	zeroTraceID             = "00000000000000000000000000000000"
	zeroParentID            = "0000000000000000"
)

type pageType struct {
	contentType  string
	cacheControl string
}

// pageTypes is the closed table of embedded file kinds. Go's mime table has
// no entry for .ttf and the distroless image has no /etc/mime.types, so every
// type is pinned here rather than looked up.
var pageTypes = map[string]pageType{
	".html": {"text/html; charset=utf-8", pageCacheControl},
	".css":  {"text/css; charset=utf-8", pageCacheControl},
	".js":   {"text/javascript; charset=utf-8", pageCacheControl},
	".ttf":  {"font/ttf", assetCacheControl},
}

// mediaTypes is the closed set of media kinds the volume may publish.
var mediaTypes = map[string]string{
	".webp": "image/webp",
	".mp4":  "video/mp4",
}

var (
	sha256Hex             = regexp.MustCompile(`^[0-9a-f]{64}$`)
	mediaName             = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.(?:webp|mp4)$`)
	inboundRequestIDShape = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	traceparentShape      = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
)
