package markdown

import "markdown.ninja/pkg/errs"

var (
	ErrMarkdownIsNotValid = func(err error) error {
		return errs.InvalidArgument("Markdown is not valid: " + err.Error())
	}
	ErrInvalidHtml = func(err error) error {
		return errs.InvalidArgument("HTML is not valid: " + err.Error())
	}
)
