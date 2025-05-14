package service

import (
	"strings"

	"markdown.ninja/pkg/markdown"
	"markdown.ninja/pkg/services/content"
	"markdown.ninja/pkg/services/websites"
)

func (service *ContentService) RenderMarkdown(website websites.Website, markdownInput string, snippets []content.Snippet, isEmail bool) (html string) {
	html, err := markdown.ToHtmlPage(
		markdownInput,
		service.httpConfig.WebsitesBaseUrl.Scheme+"://"+website.PrimaryDomain+service.httpConfig.WebsitesPort,
	)
	if err != nil {
		html = `<!-- Error: Markdown is not valid -->`
		err = nil
	}
	if strings.Contains(html, "{{<") && len(snippets) != 0 {
		snippetsMap := service.snippetsToMap(snippets)
		html = service.renderSnippets(html, snippetsMap, isEmail)
	}

	return
}

func (service *ContentService) RenderSnippets(htmlInput string, snippets []content.Snippet, isEmail bool) (ret string) {
	snippetsMap := service.snippetsToMap(snippets)
	return service.renderSnippets(htmlInput, snippetsMap, isEmail)
}

func (service *ContentService) renderSnippets(htmlInput string, snippets map[string]content.Snippet, isEmail bool) (ret string) {
	ret = service.snippetsRegexp.ReplaceAllStringFunc(htmlInput, func(rawSnippet string) string {
		snippetName := strings.TrimPrefix(rawSnippet, "{{<")
		snippetParts := strings.Fields(snippetName)
		if len(snippetParts) == 0 {
			return rawSnippet
		}
		snippetName = snippetParts[0]

		snippet, exists := snippets[snippetName]
		if exists && (snippet.RenderInEmails || !isEmail) {
			return snippet.Content
		} else if exists && isEmail && !snippet.RenderInEmails {
			return ""
		} else {
			return rawSnippet
		}
	})

	return
}

func (service *ContentService) snippetsToMap(snippets []content.Snippet) map[string]content.Snippet {
	snippetsMap := make(map[string]content.Snippet, len(snippets))
	for _, snippet := range snippets {
		snippetsMap[snippet.Name] = snippet
	}
	return snippetsMap
}
