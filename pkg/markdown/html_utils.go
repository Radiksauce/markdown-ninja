package markdown

import (
	"bytes"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// TODO: remove either md-newsletter or mdn-newsletter
var newsletterTagsRegex = regexp.MustCompile(`(?s)(<md-newsletter>.*?</md-newsletter>)|(<mdn-newsletter>.*?</mdn-newsletter>)`)

func parseAndModifyHtmlLinksAndImages(websiteBaseUrl string, htmlInput []byte) (string, error) {
	var parseAndModifyHtml func(node *html.Node)
	parseAndModifyHtml = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "a":
				for i := range node.Attr {
					if node.Attr[i].Key == "href" && strings.HasPrefix(node.Attr[i].Val, "/") {
						node.Attr[i].Val = websiteBaseUrl + node.Attr[i].Val
					}
				}
			case "img":
				for i := range node.Attr {
					if node.Attr[i].Key == "src" && strings.HasPrefix(node.Attr[i].Val, "/") {
						node.Attr[i].Val = websiteBaseUrl + node.Attr[i].Val
					}
				}
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			parseAndModifyHtml(child)
		}
	}

	htmlNodes, err := html.ParseWithOptions(bytes.NewReader(htmlInput), html.ParseOptionEnableScripting(true))
	if err != nil {
		return "", ErrInvalidHtml(err)
	}

	parseAndModifyHtml(htmlNodes)

	htmlOut := bytes.NewBuffer(make([]byte, 0, len(htmlInput)))

	// for some reasons it seems that the HTML parser adds <html><head></head><body> ... tags
	// to the input, so we need our own renderer to skip them
	var renderHtml func(node *html.Node)
	renderHtml = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "body" {
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				html.Render(htmlOut, child)
			}
			return
		} else {
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				renderHtml(child)
			}
		}
	}

	// html.Render(htmlOut, htmlNodes)
	renderHtml(htmlNodes)

	return htmlOut.String(), nil
}

func removeNewsletterTags(input []byte) []byte {
	return newsletterTagsRegex.ReplaceAll(input, []byte{})
}
