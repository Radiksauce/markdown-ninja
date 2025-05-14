package markdown_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/parser"
	"markdown.ninja/pkg/markdown"
)

func TestFrontMatterYaml(t *testing.T) {
	frontmatterSource := `date: 2021-12-07T06:00:00Z
title: "hello world"
type: "post"
tags: ["hacking", "security", "programming", "rust", "tutorial"]
authors: ["Sylvain Kerkour"]
url: "/hello-word"`
	input := fmt.Sprintf(`---
%s
---

# Hello

Some text


------------------------------

with a separator.

Something Else
--------------


Some other text.
`, frontmatterSource)

	markdownConverter := goldmark.New(
		goldmark.WithExtensions(
			markdown.FrontmatterExtension,
		),
	)
	var buf bytes.Buffer
	context := parser.NewContext()
	if err := markdownConverter.Convert([]byte(input), &buf, parser.WithContext(context)); err != nil {
		panic(err)
	}

	frontmatter, err := markdown.GetFrontmatter(context)
	if err != nil {
		t.Errorf("parsing frontmatter: err is not nil: %v", err)
	}

	title := frontmatter.Data["title"]
	if title != "hello world" {
		t.Errorf("accessing frontmatter title. Expected: \"hello world\" | got %s", title)
	}

	if frontmatter.Source != frontmatterSource {
		t.Errorf("frontmatter source. Expected: %s | got %s", frontmatterSource, frontmatter.Source)
	}
}
