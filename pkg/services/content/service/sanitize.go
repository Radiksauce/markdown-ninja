package service

func (service *ContentService) SanitizeHtml(input string) string {
	return service.xssSanitizer.Sanitize(input)
}
