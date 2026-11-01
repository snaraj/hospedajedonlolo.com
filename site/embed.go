// Package site carries the published content of hospedajedonlolo.com.
//
// The page, its stylesheet, its script and its six fonts are embedded in the
// binary byte for byte as the owner delivered them. The photographs and the
// film are too large for the image, so they live on a read-only volume; this
// package pins each of them by name, size and SHA-256 so the server can refuse
// to start rather than show a visitor anything other than the defined content.
package site

import "embed"

// Pages holds every file the server publishes from the binary. The list is
// explicit rather than a directory glob so a stray file dropped beside the
// content can never become a public URL.
//
//go:embed index.html style.css app.js assets/font-0.ttf assets/font-1.ttf assets/font-2.ttf assets/font-3.ttf assets/font-4.ttf assets/cormorant-italic-0.ttf
var Pages embed.FS
