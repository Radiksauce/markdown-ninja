package markdown

import (
	"unicode/utf8"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

type HTMLComment struct {
	Content string
	ast.BaseBlock
}

func NewHTMLComment(content string) *HTMLComment {
	return &HTMLComment{Content: content}
}

func (c *HTMLComment) Dump(source []byte, level int) {
	m := map[string]string{
		"Content": string(c.Content),
	}
	ast.DumpHelper(c, source, level, m, nil)
}

// HTMLComment is an ast.NodeKind for the HTMLComment node.
var KindHTMLComment = ast.NewNodeKind("HTMLComment")

// Kind implements ast.Node.Kind.
func (*HTMLComment) Kind() ast.NodeKind {
	return KindHTMLComment
}

type htmlCommentParser int

func NewHTMLCommentParser() parser.BlockParser {
	return htmlCommentParser(0)
}

func (htmlCommentParser) Trigger() []byte {
	return []byte{'<'}
}

func (p htmlCommentParser) Open(parent ast.Node, reader text.Reader, pc parser.Context) (ast.Node, parser.State) {
	line, startSegment := reader.PeekLine()
	pos := 0

	originalLineLenght := len(line)
	line = util.TrimLeftSpace(line)
	pos += originalLineLenght - len(line)

	if len(line) < 4 || line[0] != '<' || line[1] != '!' || line[2] != '-' || line[3] != '-' {
		return nil, parser.NoChildren
	}
	pos += 4
	line = line[4:]

	seg := startSegment
	for {
		if seg.Start+pos >= seg.Stop {
			// the HTML comment is not closed and we reached the end of the document. We quit
			break
		}

		if len(line) >= 3 && line[0] == '-' && line[1] == '-' && line[2] == '>' {
			pos = pos + 3
			reader.Advance(pos)
			break
		}

		_, runeSize := utf8.DecodeRune(line)
		line = line[runeSize:]
		pos = pos + runeSize

		if len(line) == 0 {
			reader.Advance(pos)
			line, seg = reader.PeekLine()
			pos = 0
		}
	}

	content := reader.Value(text.NewSegment(startSegment.Start+4, seg.Start+pos))

	return NewHTMLComment(string(content)), parser.NoChildren
}

func (p htmlCommentParser) Continue(node ast.Node, reader text.Reader, pc parser.Context) parser.State {
	return parser.Close
}

func (htmlCommentParser) Close(node ast.Node, reader text.Reader, pc parser.Context) {
}

// CanInterruptParagraph returns true for snippets.
func (htmlCommentParser) CanInterruptParagraph() bool {
	return false
}

func (htmlCommentParser) CanAcceptIndentedLine() bool {
	return true
}

type htmlCommentsGoldmarkExtension struct {
}

var HTMLCommentsParserExtension = &htmlCommentsGoldmarkExtension{}

func (e *htmlCommentsGoldmarkExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(
		parser.WithBlockParsers(
			util.Prioritized(NewHTMLCommentParser(), 0),
		),
	)
	m.Renderer().AddOptions(
		renderer.WithNodeRenderers(
			util.Prioritized(newHtmlCommentsRenderer(), 500),
		),
	)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Renderer
////////////////////////////////////////////////////////////////////////////////////////////////////

type htmlCommentsRenderer struct{}

func newHtmlCommentsRenderer() renderer.NodeRenderer {
	return &htmlCommentsRenderer{}
}

// RegisterFuncs implements NodeRenderer.RegisterFuncs.
func (r *htmlCommentsRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(KindHTMLComment, r.render)
}

func (r *htmlCommentsRenderer) render(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	// if entering {
	// 	snippet := node.(*Snippet)
	// 	content := append(snippet.Content, '\n')
	// 	w.Write(content)
	// }

	return ast.WalkContinue, nil
}
