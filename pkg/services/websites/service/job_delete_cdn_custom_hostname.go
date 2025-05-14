package service

// func (service *WebsitesService) JobDeleteCdnCustomHostname(ctx context.Context, input websites.JobDeleteCdnCustomHostname) (err error) {
// 	logger := slogx.FromCtx(ctx)

// 	err = service.cdn.RemoveHostname(ctx, input.CdnHostnameID)
// 	if err != nil {
// 		errMessage := "websites.JobDeleteCdnCustomHostname: Removing hostname from CDN"
// 		logger.Error(errMessage, slogx.Err(err), slog.String("hostname", input.Hostname))
// 		err = websites.ErrRemovingDomain(input.Hostname)
// 		return
// 	}

// 	return
// }
