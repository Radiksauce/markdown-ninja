package markdown

import (
	"testing"
)

func TestParseAndModifyHtmlLinksAndImages(t *testing.T) {
	input := `
<div>
<a href="/some-link" class="nothing">some link</a>
<a href="https://markdown.ninja/another-link" class="nothing">another link</a>
</div>

<div>
<img src="/some-image.jpg" class="nothing" alt="some image"/>
<img src="https://markdown.ninja/another-image.jpg" class="nothing" alt="another image"/>
</div>
`
	expected := `<div>
<a href="https://markdown.club/some-link" class="nothing">some link</a>
<a href="https://markdown.ninja/another-link" class="nothing">another link</a>
</div>

<div>
<img src="https://markdown.club/some-image.jpg" class="nothing" alt="some image"/>
<img src="https://markdown.ninja/another-image.jpg" class="nothing" alt="another image"/>
</div>
`

	output, err := parseAndModifyHtmlLinksAndImages("https://markdown.club", []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if output != expected {
		t.Error("Invalid output. Got:", output)
		t.Error("Expected:", expected)
	}
}

func TestRemoveNewsletterTags(t *testing.T) {
	input := `<div>
<md-newsletter>something</md-newsletter>

A

<md-newsletter>

  something else

</md-newsletter>

B

<mdn-newsletter>something mdn</mdn-newsletter>

C

<mdn-newsletter>

  something else mdn

</mdn-newsletter>

D
</div>
`
	expected := `<div>


A



B



C



D
</div>
`

	output := removeNewsletterTags([]byte(input))
	if string(output) != expected {
		t.Error("Invalid output. Got:", string(output))
		t.Error("Expected:", expected)
	}
}
