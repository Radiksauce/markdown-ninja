package markdown_test

import (
	"bytes"
	"testing"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/parser"
	"markdown.ninja/pkg/markdown"
)

func TestHtmlComments(t *testing.T) {
	input := `
    <!-- this is a comment before title -->
# Hello
<!-- this is a comment after title -->

Some text
`
	expected := `<h1>Hello</h1>
<p>Some text</p>
`

	markdownConverter := goldmark.New(
		goldmark.WithExtensions(
			markdown.HTMLCommentsParserExtension,
		),
	)
	var buf bytes.Buffer
	context := parser.NewContext()
	if err := markdownConverter.Convert([]byte(input), &buf, parser.WithContext(context)); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if output != expected {
		t.Error("Invalid output. Got:", output)
		t.Error("Expected:", expected)
	}
}
