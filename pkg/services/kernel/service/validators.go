package service

import (
	"context"
	"encoding/hex"
	"net/mail"
	"strings"
	"time"

	"github.com/bloom42/stdx-go/log/slogx"
	"github.com/bloom42/stdx-go/retry"
	"github.com/bloom42/stdx-go/stringsx"
	"github.com/bloom42/stdx-go/validate"
	"markdown.ninja/pingoo-go"
	"markdown.ninja/pkg/services/kernel"
)

// var paletteColorRegexp = regexp.MustCompile("var\\(--test-palette-[1-8]\\)")

func (service *KernelService) ValidateEmail(ctx context.Context, emailAddress string, rejectBlockedDomains bool) (err error) {
	if emailAddress == "" {
		return kernel.ErrEmailIsNotValid
	}

	if len(emailAddress) > kernel.EmailMaxLength {
		return kernel.ErrEmailIsNotValid
	}

	if !stringsx.IsLower(emailAddress) {
		return kernel.ErrEmailIsNotValid
	}

	if !validate.IsASCII(emailAddress) {
		return kernel.ErrEmailIsNotValid
	}

	_, err = mail.ParseAddress(emailAddress)
	if err != nil {
		return kernel.ErrEmailIsNotValid
	}

	if strings.Contains(emailAddress, ",") || strings.Contains(emailAddress, " ") {
		return kernel.ErrEmailIsNotValid
	}

	if !validate.IsEmail(emailAddress) {
		return kernel.ErrEmailIsNotValid
	}

	emailParts := strings.Split(emailAddress, "@")

	if len(emailParts) != 2 {
		return kernel.ErrEmailIsNotValid
	}

	if rejectBlockedDomains && service.pingooClient != nil {
		var pingooRes pingoo.EmailInfo
		err = retry.Do(func() (retryErr error) {
			pingooRes, retryErr = service.pingooClient.CheckEmailAddress(ctx, emailAddress)
			return retryErr
		}, retry.Context(ctx), retry.Attempts(3), retry.Delay(100*time.Millisecond))
		if err != nil {
			logger := slogx.FromCtx(ctx)
			logger.Error("checking email address with Pingoo", slogx.Err(err))
			err = nil
		} else {
			if !pingooRes.Valid || pingooRes.Disposable || !pingooRes.MxRecords {
				return kernel.ErrEmailIsNotValid
			}
		}
	}

	return
}

func (service *KernelService) ValidateColor(color string) (err error) {
	// if acceptPalette && paletteColorRegexp.Match([]byte(color)) {
	// 	return nil
	// }

	if (len(color) != 7 && len(color) != 9) || !strings.HasPrefix(color, "#") {
		err = kernel.ErrColorIsNotValid
		return err
	}

	_, err = hex.DecodeString(color[1:])
	if err != nil {
		err = kernel.ErrColorIsNotValid
		return err
	}

	return nil
}
