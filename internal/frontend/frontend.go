// Package frontend embeds the Vue SPA dist directory for serving from the Go binary.
// The dist/ directory is populated by the build process (scripts/build-all.sh copies
// web/dist/ here). A placeholder index.html is committed for development builds.
package frontend

import "embed"

// Assets contains the embedded Vue SPA build output.
// The build process copies web/dist/* into internal/frontend/dist/ before compilation.
//
//go:embed dist/*
var Assets embed.FS
