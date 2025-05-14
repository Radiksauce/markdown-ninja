package webapp

import (
	"embed"
	"io/fs"
)

//go:embed dist/*
var webapp embed.FS

// embed.FS does not keep the good file.ModTime() for reproductability
// which prevent us to implement a good caching startegy for webapp's assets
// see https://github.com/golang/go/issues/45445
// https://github.com/golang/go/issues/44854
// https://forum.golangbridge.org/t/embed-file-modtime-returns-time-time-instead-of-the-files-modification-time-at-the-time-it-was-embedded/22684/3
// there is a potential workaround of using a fixed modifiedAt = time.Now().UTC().Truncate(time.Second)
// but it's not great in a multi server scenario
// func webappFS() fs.FS {
// 	return os.DirFS(filepath.Join("assets", "webapp"))
// }

// FS returns an `fs.FS` with the webapp at its root
func FS() fs.FS {
	webappFs, _ := fs.Sub(webapp, "dist")
	return webappFs
}
