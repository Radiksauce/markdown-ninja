package markdown

import (
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

type absoluteUrlsExtension struct {
	websiteBaseUrl string
	images         bool
	links          bool
}

func NewAbsoluteUrlsExtension(websiteBaseUrl string, images, links bool) *absoluteUrlsExtension {
	return &absoluteUrlsExtension{
		websiteBaseUrl,
		images,
		links,
	}
}

func (extension *absoluteUrlsExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(
		parser.WithASTTransformers(
			util.Prioritized(newAbsolutUrlsASTTransformer(extension.websiteBaseUrl, extension.images, extension.links), 500),
		),
	)
}

func newAbsolutUrlsASTTransformer(websiteBaseUrl string, rewriteImages, rewriteLinks bool) parser.ASTTransformer {
	return absoluteUrlsAstTransformer{
		websiteBaseUrl,
		rewriteImages,
		rewriteLinks,
	}
}

type absoluteUrlsAstTransformer struct {
	websiteBaseUrl string
	rewriteImages  bool
	rewriteLinks   bool
}

func (transformer absoluteUrlsAstTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	replaceUrls := func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}

		kind := node.Kind()

		if kind == ast.KindImage && transformer.rewriteImages {

			img := node.(*ast.Image)

			if strings.HasPrefix(strings.TrimSpace(string(img.Destination)), "/") {
				img.Destination = []byte(transformer.websiteBaseUrl + string(img.Destination))
				// url, err := url.Parse(string(img.Destination))
				// if err != nil {
				// 	return ast.WalkContinue, nil
				// }
				// url.Scheme = transformer.protocol
				// url.Host = transformer.host
				// img.Destination = []byte(url.String())
			}
		} else if kind == ast.KindLink && transformer.rewriteLinks {

			link := node.(*ast.Link)

			if strings.HasPrefix(strings.TrimSpace(string(link.Destination)), "/") {
				link.Destination = []byte(transformer.websiteBaseUrl + string(link.Destination))
				// url, err := url.Parse(string(link.Destination))
				// if err != nil {
				// 	return ast.WalkContinue, nil
				// }
				// url.Scheme = transformer.protocol
				// url.Host = transformer.host
				// link.Destination = []byte(url.String())
			}
		}

		return ast.WalkContinue, nil
	}

	ast.Walk(node, replaceUrls)
}
