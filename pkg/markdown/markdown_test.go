package markdown

import (
	"testing"
)

func TestMarkdown(t *testing.T) {
	input := `
    <!-- this is a comment before title -->
# Hello
<!-- this is a comment after title -->

Some text

* first item
* second item

| header 1 | header 2|
| --- | --- |
| 1x1 | 1x2 |
| 2x1 | 2x2 |

[some relative link](/some-relative-link)

[some absolute link](https://markdown.ninja/some-absolute-link)
`
	expected := `<h1 id="hello">Hello</h1>
<p>Some text</p>
<ul>
<li>first item</li>
<li>second item</li>
</ul>
<table>
<thead>
<tr>
<th>header 1</th>
<th>header 2</th>
</tr>
</thead>
<tbody>
<tr>
<td>1x1</td>
<td>1x2</td>
</tr>
<tr>
<td>2x1</td>
<td>2x2</td>
</tr>
</tbody>
</table>
<p><a href="https://markdown.ninja/some-relative-link">some relative link</a></p>
<p><a href="https://markdown.ninja/some-absolute-link">some absolute link</a></p>
`

	output, err := ToHtmlPage(input, "https://markdown.ninja")
	if err != nil {
		t.Fatal(err)
	}
	if output != expected {
		t.Error("Invalid output. Got:", output)
		t.Error("Expected:", expected)
	}
}
