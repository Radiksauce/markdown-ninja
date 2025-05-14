package pingoo

import (
	"context"
	"fmt"
	"net/http"
)

func (client *Client) CheckEmailAddress(ctx context.Context, email string) (res EmailInfo, err error) {
	err = client.request(ctx, requestParams{
		Method: http.MethodGet,
		Route:  fmt.Sprintf("/email/%s", email),
	}, &res)
	return
}
