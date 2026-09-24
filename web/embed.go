// Package web embeds the built RTBH dashboard served by rtbh-server.
package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var files embed.FS

// Dist returns the production frontend rooted at dist.
func Dist() fs.FS {
	subtree, err := fs.Sub(files, "dist")
	if err != nil {
		panic(err)
	}
	return subtree
}
