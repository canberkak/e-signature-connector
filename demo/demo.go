package demo

import (
	"embed"
	"net/http"
)

//go:embed index.html
var files embed.FS

func Handler() http.Handler {
	return http.FileServerFS(files)
}
