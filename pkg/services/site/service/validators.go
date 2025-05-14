package service

import (
	"markdown.ninja/pkg/services/site"
)

func (service *SiteService) validateRangeRequest(rangeHeader string) error {
	if len(rangeHeader) > site.RangeHeaderMaxSize {
		return site.ErrRangeRequestIsNotValid
	}

	if !site.RangeHeaderRegexp.MatchString(rangeHeader) {
		return site.ErrRangeRequestIsNotValid
	}

	return nil
}
