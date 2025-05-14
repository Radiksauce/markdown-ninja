package cachecontrol

const (
	NoCache = "private, no-cache, no-store, must-revalidate"
	Dynamic = "public, no-cache, must-revalidate"
	// CacheControl10Minutes = "public, max-age=600, stale-while-revalidate=600"
	// CacheControl15Minutes = "public, max-age=900, stale-while-revalidate=900"
	Immutable = "public, max-age=31536000, immutable"
)

const (
	WebsitePage      = Dynamic
	WebsiteAsset     = "public, max-age=300, stale-while-revalidate=2592000" // 30 days
	WebsiteFeed      = "public, max-age=300, stale-while-revalidate=3600"
	WebsiteRobotsTxt = "public, max-age=300, stale-while-revalidate=3600"
	WebsiteSitemap   = "public, max-age=300, stale-while-revalidate=3600"
	WebsiteFavicon   = "public, max-age=30, stale-while-revalidate=2592000" // 30 days

	HeadlessApiPages = "public, max-age=0, stale-while-revalidate=3600"
	HeadlessApiTags  = "public, max-age=10, stale-while-revalidate=3600"
)
