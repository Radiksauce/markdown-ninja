package mdninja

import (
	"fmt"

	"markdown.ninja/pkg/buildinfo"
)

var (
	UserAgent = fmt.Sprintf("Markdown Ninja/%s (https://markdown.ninja)", buildinfo.Version)
)
