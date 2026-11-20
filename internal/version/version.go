// Package version holds the build version.
package version

// Version is overridden at link time with -ldflags "-X wyrm/internal/version.Version=...".
var Version = "0.1.0-dev"
