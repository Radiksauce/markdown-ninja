package service

func (service *WebsitesService) getSubdomainForSlug(slug string) string {
	websitesRootDomain := service.config.HTTP.WebsitesRootDomain
	return slug + "." + websitesRootDomain
}
