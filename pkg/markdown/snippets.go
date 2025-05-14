package markdown

import (
	"bytes"
	"unicode"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// Snippet represents a snippet element and its contents, e.g. `{{< examples >}}`.
type Snippet struct {
	ast.BaseBlock

	Name    []byte
	Content []byte
}

func (s *Snippet) Dump(source []byte, level int) {
	m := map[string]string{
		"Name": string(s.Name),
	}
	ast.DumpHelper(s, source, level, m, nil)
}

// KindSnippet is an ast.NodeKind for the Snippet node.
var KindSnippet = ast.NewNodeKind("Snippet")

// Kind implements ast.Node.Kind.
func (*Snippet) Kind() ast.NodeKind {
	return KindSnippet
}

func NewSnippet(name, content []byte) *Snippet {
	return &Snippet{Name: name, Content: content}
}

type snippetParser int

// NewSnippetParser returns a BlockParser that parses snippet (e.g. `{{< examples >}}`).
func NewSnippetParser() parser.BlockParser {
	return snippetParser(0)
}

func (snippetParser) Trigger() []byte {
	return []byte{'{'}
}

func (snippetParser) parseSnippet(line []byte, pos int) (int, int, int, bool, bool) {
	// Look for `{{<` to open the snippet.
	text := line[pos:]
	if len(text) < 3 || text[0] != '{' || text[1] != '{' || text[2] != '<' {
		return 0, 0, 0, false, false
	}
	text, pos = text[3:], pos+3

	// Scan through whitespace.
	for {
		if len(text) == 0 {
			return 0, 0, 0, false, false
		}

		r, sz := utf8.DecodeRune(text)
		if !unicode.IsSpace(r) {
			break
		}
		text, pos = text[sz:], pos+sz
	}

	// Check for a '/' to indicate that this is a closing snippet.
	isClose := false
	if text[0] == '/' {
		isClose = true
		text, pos = text[1:], pos+1
	}

	// Find the end of the name and the closing delimiter (`>}}`) for this snippet.
	nameStart, nameEnd, inName := pos, pos, true
	for {
		if len(text) == 0 {
			return 0, 0, 0, false, false
		}

		if len(text) >= 3 && text[0] == '>' && text[1] == '}' && text[2] == '}' {
			if inName {
				nameEnd = pos
			}
			text, pos = text[3:], pos+3
			break
		}

		r, sz := utf8.DecodeRune(text)
		if inName && unicode.IsSpace(r) {
			nameEnd, inName = pos, false
		}
		text, pos = text[sz:], pos+sz
	}

	return nameStart, nameEnd, pos, isClose, true
}

func (p snippetParser) Open(parent ast.Node, reader text.Reader, pc parser.Context) (ast.Node, parser.State) {
	line, _ := reader.PeekLine()
	pos := pc.BlockOffset()
	if pos < 0 {
		return nil, parser.NoChildren
	}

	nameStart, nameEnd, snippetEnd, isClose, ok := p.parseSnippet(line, pos)
	if !ok || isClose {
		return nil, parser.NoChildren
	}
	name := line[nameStart:nameEnd]
	content := line[pos:snippetEnd]

	reader.Advance(snippetEnd)

	return NewSnippet(name, content), parser.HasChildren
}

func (p snippetParser) Continue(node ast.Node, reader text.Reader, pc parser.Context) parser.State {
	line, seg := reader.PeekLine()
	pos := pc.BlockOffset()
	if pos < 0 {
		return parser.Continue | parser.HasChildren
	} else if pos > seg.Len() {
		return parser.Continue | parser.HasChildren
	}

	nameStart, nameEnd, snippetEnd, isClose, ok := p.parseSnippet(line, pos)
	if !ok || !isClose {
		return parser.Continue | parser.HasChildren
	}

	snippet := node.(*Snippet)
	if !bytes.Equal(line[nameStart:nameEnd], snippet.Name) {
		return parser.Continue | parser.HasChildren
	}

	reader.Advance(snippetEnd)
	return parser.Close
}

func (snippetParser) Close(node ast.Node, reader text.Reader, pc parser.Context) {
}

// CanInterruptParagraph returns true for snippets.
func (snippetParser) CanInterruptParagraph() bool {
	return true
}

// CanAcceptIndentedLine returns false for snippets; all snippets must start at the first column.
func (snippetParser) CanAcceptIndentedLine() bool {
	return true
}

type snippetsGoldmarkExtension struct {
}

// At the moment we only support block snippets on one line
var SnippetsParserExtension = &snippetsGoldmarkExtension{}

func (e *snippetsGoldmarkExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(
		parser.WithBlockParsers(
			util.Prioritized(NewSnippetParser(), 0),
		),
	)
	m.Renderer().AddOptions(
		renderer.WithNodeRenderers(
			util.Prioritized(newSnippetIgnoreRenderer(), 500),
		),
	)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Renderer
////////////////////////////////////////////////////////////////////////////////////////////////////

// snippetIgnoreRenderer struct is a renderer.NodeRenderer implementation for the extension.
type snippetIgnoreRenderer struct{}

// newSnippetIgnoreRenderer builds a new HTMLRenderer with given options and returns it.
func newSnippetIgnoreRenderer() renderer.NodeRenderer {
	return &snippetIgnoreRenderer{}
}

// RegisterFuncs implements NodeRenderer.RegisterFuncs.
func (r *snippetIgnoreRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(KindSnippet, r.render)
}

func (r *snippetIgnoreRenderer) render(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		snippet := node.(*Snippet)
		content := append(snippet.Content, '\n')
		w.Write(content)
	}

	return ast.WalkContinue, nil
}
