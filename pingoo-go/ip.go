package pingoo

import (
	"context"
	"fmt"
	"net/http"
)

func (client *Client) CheckIpAddress(ctx context.Context, ipAddress string) (res IpInfo, err error) {
	err = client.request(ctx, requestParams{
		Method: http.MethodGet,
		Route:  fmt.Sprintf("/ip/%s", ipAddress),
	}, &res)
	return
}
