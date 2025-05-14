package kernel

type JobRefreshGeoipDatabase struct{}

func (JobRefreshGeoipDatabase) JobType() string {
	return "kernel.refresh_geoip_database"
}
