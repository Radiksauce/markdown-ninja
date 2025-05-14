package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
)

func (service *KernelService) Init(ctx context.Context, input kernel.EmptyInput) (ret kernel.InitData, err error) {
	httpCtx := httpctx.FromCtx(ctx)

	ret = kernel.InitData{
		StripePublicKey: service.stripePublicKey,
		Country:         httpCtx.Client.CountryCode,
		ContactEamil:    service.emailsConfig.ContactAddress.Address,
		Pricing: []kernel.Plan{
			kernel.PlanFree,
			kernel.PlanPro,
			kernel.PlanEnterprise,
		},
		Pingoo: kernel.InitDataPingoo{
			AppID:    service.pingooConfig.AppID,
			Endpoint: service.pingooConfig.Endpoint,
		},
		WebsitesBaseUrl: service.config.HTTP.WebsitesBaseUrl.String(),
	}
	return ret, nil
}
