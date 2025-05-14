package middlewares

import (
	"net/url"
	"testing"
)

func mustParseUrl(t *testing.T, input string) *url.URL {
	ret, err := url.Parse(input)
	if err != nil {
		t.Errorf("error parsing URL: %s: %v", input, err)
	}
	return ret
}

func TestGenerateRedirectUrl(t *testing.T) {
	tests := []struct {
		Host     string
		URL      *url.URL
		Expected string
	}{
		{
			Host:     "markdown.ninja",
			URL:      mustParseUrl(t, "https://markdown.ninja"),
			Expected: "https://markdown.ninja",
		},
		{
			Host:     "markdown.ninja",
			URL:      mustParseUrl(t, "https://markdown.ninja?hello=world"),
			Expected: "https://markdown.ninja?hello=world",
		},
		{
			Host:     "markdown.ninja",
			URL:      mustParseUrl(t, "https://markdown.ninja?hello=world"),
			Expected: "https://markdown.ninja?hello=world",
		},
		{
			Host:     "markdown.ninja",
			URL:      mustParseUrl(t, "https://markdown.ninja?hello=world&a=b"),
			Expected: "https://markdown.ninja?hello=world&a=b",
		},
	}

	for _, test := range tests {
		res := generateRedirectUrl(test.URL, test.Host)
		if res != test.Expected {
			t.Errorf("expected: %s | got: %s | Host: %s, URL: %s", test.Expected, res, test.Host, test.URL.String())
		}
	}
}

func TestStripWwwSubdomain(t *testing.T) {
	tests := []struct {
		Host     string
		Expected string
	}{
		{
			Host:     "markdown.ninja",
			Expected: "markdown.ninja",
		},
		{
			Host:     "www.markdown.ninja",
			Expected: "markdown.ninja",
		},
		{
			Host:     "www.com",
			Expected: "www.com",
		},
		{
			Host:     "www.www.com",
			Expected: "www.com",
		},
	}

	for _, test := range tests {
		res := stripWwwSubdomain(test.Host)
		if res != test.Expected {
			t.Errorf("expected: %s | got: %s | Host: %s", test.Expected, res, test.Host)
		}
	}
}
