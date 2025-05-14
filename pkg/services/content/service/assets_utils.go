package service

import (
	"fmt"
	"time"
)

func (service *ContentService) generateDefaultAssetFolder() (folder string) {
	now := time.Now().UTC()
	year, month, _ := now.Date()

	folder = fmt.Sprintf("/assets/%d/%02d", year, month)

	return
}
