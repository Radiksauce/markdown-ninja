package pandoc

import (
	_ "embed"
)

//go:embed epub.css
var EpubCss []byte

//go:embed inline_code.tex
var InlineCodeTex []byte

//go:embed settings_template.yml
var SettingsTemplate []byte

//go:embed tango_modified.json
var ThemeTango []byte

//go:embed default_cover.png
var DefaultCover []byte

type SettingsTemplateData struct {
	Title      string
	Subtitle   string
	Author     string
	Cover      string
	Tags       []string
	Identifier string
}
