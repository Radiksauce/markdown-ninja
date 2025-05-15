package assets

import (
	_ "embed"
)

//go:embed pingoo.wasm
var PingooWasm []byte

// wat2wasm memory.wat --output=memory.wasm --enable-threads
//
//go:embed memory.wasm
var MemoryWasm []byte
