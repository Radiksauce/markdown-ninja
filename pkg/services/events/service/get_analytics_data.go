package service

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"
	"markdown.ninja/pkg/services/events"
)

func (service *Service) GetAnalyticsData(ctx context.Context, input events.GetAnalyticsInput) (ret events.AnalyticsData, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
	if err != nil {
		return
	}

	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Add(-30 * 24 * time.Hour)
	to := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, now.Location())

	pageViewsAndVisitors, err := service.repo.GetPageViewsAndVisitors(ctx, service.eventsDb, input.WebsiteID, from, to)
	if err != nil {
		return
	}

	ret = events.AnalyticsData{
		PageViews:      make([]events.Counter, 0, len(pageViewsAndVisitors)),
		Visitors:       make([]events.Counter, 0, len(pageViewsAndVisitors)),
		Pages:          []events.Counter{},
		Referrers:      []events.Counter{},
		Countries:      []events.Counter{},
		Browsers:       []events.CounterBrowser{},
		OSes:           []events.CounterOperatingSystem{},
		NewSubscribers: 0,
	}

	for _, dailyData := range pageViewsAndVisitors {
		ret.PageViews = append(ret.PageViews, events.Counter{
			Label: dailyData.Day.Format(time.RFC3339),
			Count: dailyData.PageViews,
		})
		ret.TotalPageViews += dailyData.PageViews
		ret.Visitors = append(ret.Visitors, events.Counter{
			Label: dailyData.Day.Format(time.RFC3339),
			Count: dailyData.Visitors,
		})
		ret.TotalVisitors += dailyData.Visitors
	}

	errGroup, ctx := errgroup.WithContext(ctx)
	// for now we use a concurrency limit of 3 to balance between latency and database usage
	errGroup.SetLimit(3)

	errGroup.Go(func() error {
		var taskErr error
		ret.Pages, taskErr = service.repo.GetTopPages(ctx, service.eventsDb, input.WebsiteID, from, to, 10)
		return taskErr
	})

	errGroup.Go(func() error {
		var taskErr error
		ret.Countries, taskErr = service.repo.GetTopCountries(ctx, service.eventsDb, input.WebsiteID, from, to, 10)
		return taskErr
	})

	errGroup.Go(func() error {
		var taskErr error
		ret.Referrers, taskErr = service.repo.GetTopReferrers(ctx, service.eventsDb, input.WebsiteID, from, to, 10)
		if taskErr != nil {
			return taskErr
		}

		for i, tuple := range ret.Referrers {
			if tuple.Label == "" {
				ret.Referrers[i].Label = "(direct)"
				break
			}
		}
		return nil
	})

	errGroup.Go(func() error {
		var taskErr error
		ret.Browsers, taskErr = service.repo.GetTopBrowsers(ctx, service.eventsDb, input.WebsiteID, from, to, 10)
		return taskErr
	})

	errGroup.Go(func() error {
		var taskErr error
		ret.OSes, taskErr = service.repo.GetTopOses(ctx, service.eventsDb, input.WebsiteID, from, to, 10)
		return taskErr
	})

	errGroup.Go(func() error {
		var taskErr error
		ret.NewSubscribers, taskErr = service.repo.GetNewSubscribersCount(ctx, service.eventsDb, input.WebsiteID, from, to)
		return taskErr
	})

	err = errGroup.Wait()
	if err != nil {
		return
	}

	return
}
