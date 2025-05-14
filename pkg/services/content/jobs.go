package content

type JobDeleteAssetData struct {
	StorageKey string `json:"storage_key"`
}

func (JobDeleteAssetData) JobType() string {
	return "content.delete_asset_data"
}

type JobDeleteAssetsDataWithPrefix struct {
	Prefix string `json:"prefix"`
}

func (JobDeleteAssetsDataWithPrefix) JobType() string {
	return "content.delete_assets_data_with_prefix"
}

type JobPublishPages struct {
}

func (JobPublishPages) JobType() string {
	return "content.publish_pages"
}
