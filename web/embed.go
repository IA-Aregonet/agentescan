package web

import "embed"

// FS embeds the dashboard static assets into the binary.
//
//go:embed index.html css/* js/*
var FS embed.FS
