package service

import (
	"fmt"
	"testing"

	"markdown.ninja/pkg/services/websites"
)

type matchRedirectTest struct {
	Path        string
	Redirect    websites.Redirect
	Matched     bool
	Destination string
}

func TestMatchRedirectAndReplace(t *testing.T) {
	redirects := []websites.Redirect{
		{PathPattern: "/old", To: "/new"},
		{PathPattern: "/blog/:post", To: "/:post"},
		{PathPattern: "/:year/:month/:post", To: "/:month/:year/:post"},
		{PathPattern: "/old/*", To: "/404"},
		{PathPattern: "/old*", To: "/404"},
		{PathPattern: "/*", To: "/"},
		{PathPattern: "/blog/*", To: "/:splat"},
	}
	tests := []matchRedirectTest{
		{
			Path:        "/old",
			Redirect:    redirects[0],
			Matched:     true,
			Destination: "/new",
		},
		{
			Path:        "/old/other",
			Redirect:    redirects[0],
			Matched:     false,
			Destination: "",
		},
		{
			Path:        "/blog/article",
			Redirect:    redirects[1],
			Matched:     true,
			Destination: "/article",
		},
		{
			Path:        "/blog/article/other",
			Redirect:    redirects[1],
			Matched:     false,
			Destination: "",
		},
		{
			Path:        "/2021/12/hello",
			Redirect:    redirects[2],
			Matched:     true,
			Destination: "/12/2021/hello",
		},
		{
			Path:        "/old/article",
			Redirect:    redirects[3],
			Matched:     true,
			Destination: "/404",
		},
		{
			Path:        "/old/",
			Redirect:    redirects[3],
			Matched:     true,
			Destination: "/404",
		},
		{
			Path:        "/old",
			Redirect:    redirects[3],
			Matched:     false,
			Destination: "",
		},
		{
			Path:        "/old",
			Redirect:    redirects[4],
			Matched:     true,
			Destination: "/404",
		},
		{
			Path:        "/oldish",
			Redirect:    redirects[4],
			Matched:     true,
			Destination: "/404",
		},
		{
			Path:        "/article",
			Redirect:    redirects[5],
			Matched:     true,
			Destination: "/",
		},
		{
			Path:        "/other/article",
			Redirect:    redirects[5],
			Matched:     true,
			Destination: "/",
		},
		{
			Path:        "/blog/article",
			Redirect:    redirects[6],
			Matched:     true,
			Destination: "/article",
		},
		{
			Path:        "/blog/",
			Redirect:    redirects[6],
			Matched:     true,
			Destination: "/",
		},
		{
			Path:        "/blog",
			Redirect:    redirects[6],
			Matched:     false,
			Destination: "",
		},
		{
			Path:        "/blog/nested/article",
			Redirect:    redirects[6],
			Matched:     true,
			Destination: "/nested/article",
		},
	}

	for _, test := range tests {
		testname := fmt.Sprintf("%s|%s|%s", test.Path, test.Redirect.PathPattern, test.Redirect.To)
		t.Run(testname, func(t *testing.T) {
			matched, destination := matchRedirectAndReplace(test.Path, test.Redirect.PathPattern, test.Redirect.To)
			if matched != test.Matched || destination != test.Destination {
				t.Errorf("got: matched(%v), destination(%s) | want matched(%v), destination(%s)", matched, destination, test.Matched, test.Destination)
			}
		})
	}
}
