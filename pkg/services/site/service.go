package site

import (
	"context"
	"net/http"

	"markdown.ninja/pkg/services/kernel"
)

type Service interface {
	// contacts
	GetMe(ctx context.Context, input kernel.EmptyInput) (ret *Contact, err error)
	Login(ctx context.Context, input LoginInput) (ret LoginOutput, err error)
	CompleteLogin(ctx context.Context, input CompleteLoginInput) (contact Contact, err error)
	Subscribe(ctx context.Context, input SubscribeInput) (ret SubscribeOutput, err error)
	CompleteSubscription(ctx context.Context, input CompleteSubscriptionInput) (contact Contact, err error)
	Logout(ctx context.Context, input kernel.EmptyInput) (err error)
	Unsubscribe(ctx context.Context, input UnsubscribeInput) (err error)
	UpdateMyAccount(ctx context.Context, input UpdateMyAccount) (contact Contact, err error)
	DeleteMyAccount(ctx context.Context, _ kernel.EmptyInput) (err error)

	// products / orders
	ListMyOrders(ctx context.Context, input kernel.EmptyInput) (ret kernel.PaginatedResult[Order], err error)
	ListMyProducts(ctx context.Context, input kernel.EmptyInput) (ret kernel.PaginatedResult[Product], err error)
	GetProduct(ctx context.Context, input GetProductInput) (ret Product, err error)

	// website
	GetWebsite(ctx context.Context, input kernel.EmptyInput) (ret Website, err error)

	// Content
	GetPage(ctx context.Context, input GetPageInput) (ret Page, err error)
	ListTags(ctx context.Context, input kernel.EmptyInput) (ret kernel.PaginatedResult[Tag], err error)
	ListPages(ctx context.Context, input ListPagesInput) (ret kernel.PaginatedResult[PageMetadata], err error)
	ServeContent(res http.ResponseWriter, req *http.Request)
	ServePreview(res http.ResponseWriter, req *http.Request)

	// Others
	// TrackEventPageView is needed by special pages (ex: /blog) that don't require a headless API
	// call
	TrackEventPageView(ctx context.Context, input TrackEventPageViewInput) (err error)

	// Jobs
	JobSendLoginEmail(ctx context.Context, data JobSendLoginEmail) (err error)
	JobSendSubscribeEmail(ctx context.Context, data JobSendSubscribeEmail) (err error)

	// Tasks
}
