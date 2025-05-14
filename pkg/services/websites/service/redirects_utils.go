package service

import (
	"context"
	"strings"

	"markdown.ninja/pkg/services/websites"
)

func (service *WebsitesService) MatchRedirect(ctx context.Context, domain, path string, redirects []websites.Redirect) *websites.Redirect {
	for _, redirect := range redirects {
		if redirect.Domain == "" || redirect.Domain == domain {
			matched, destination := matchRedirectAndReplace(path, redirect.PathPattern, redirect.To)
			if matched {
				redirect.To = destination
				return &redirect
			}
		}
	}

	return nil
}

type redirectsDiff struct {
	RedirectsToCreate []websites.RedirectInput
	RedirectsToRemove []websites.Redirect
}

func (service *WebsitesService) diffRedirects(siteRedirects []websites.Redirect, newRedirects []websites.RedirectInput) (diff redirectsDiff) {
	diff = redirectsDiff{
		RedirectsToCreate: []websites.RedirectInput{},
		RedirectsToRemove: []websites.Redirect{},
	}

	existingRedirectsMap := make(map[string]websites.Redirect, len(siteRedirects))
	for _, redirect := range siteRedirects {
		existingRedirectsMap[redirect.Pattern] = redirect
	}

	newRedirectsMap := make(map[string]websites.RedirectInput, len(newRedirects))
	for _, redirect := range newRedirects {
		redirect.Pattern = strings.TrimSpace(redirect.Pattern)
		newRedirectsMap[redirect.Pattern] = redirect
	}

	for _, siteRedirect := range siteRedirects {
		if _, isInNewRedirects := newRedirectsMap[siteRedirect.Pattern]; !isInNewRedirects {
			diff.RedirectsToRemove = append(diff.RedirectsToRemove, siteRedirect)
		}
	}

	for pattern, redirect := range newRedirectsMap {
		if _, alreadyExists := existingRedirectsMap[pattern]; !alreadyExists {
			diff.RedirectsToCreate = append(diff.RedirectsToCreate, redirect)
		}
	}

	return
}

func matchRedirectAndReplace(path, pattern string, to string) (matched bool, destination string) {
	destination = to

	for pattern != "" && path != "" {

		switch pattern[0] {
		case ':':
			// ':' matches till next slash in path
			nextPatternSlash := strings.IndexByte(pattern, '/')
			if nextPatternSlash < 0 {
				nextPatternSlash = len(pattern)
			}
			varName := pattern[:nextPatternSlash]
			pattern = pattern[nextPatternSlash:]

			nextPathSlash := strings.IndexByte(path, '/')
			if nextPathSlash < 0 {
				nextPathSlash = len(path)
			}
			capturedPath := path[:nextPathSlash]
			path = path[nextPathSlash:]

			destination = strings.ReplaceAll(destination, varName, capturedPath)
		case '*':
			matched = true
			destination = strings.ReplaceAll(destination, ":splat", path)
			return
			// pattern = pattern[1:]
			// if len(pattern) == 0 {
			// 	path = ""
			// } else {
			// 	nextByte := pattern[0]
			// 	// '*' matches till next slash in path
			// 	nextPathByte := strings.IndexByte(path, nextByte)
			// 	if nextPathByte < 0 {
			// 		nextPathByte = len(path)
			// 	}
			// 	path = path[nextPathByte:]
			// }

		case path[0]:
			// non-'*' pattern byte must match path byte
			path = path[1:]
			pattern = pattern[1:]
		default:
			destination = ""
			return
		}
	}

	if (pattern == "" || pattern == "*") && path == "" {
		matched = true
		if pattern == "*" {
			destination = strings.ReplaceAll(destination, ":splat", path)
		}
	} else {
		destination = ""
	}

	return
}
