package client

import (
	"fmt"
)

var (
	ErrReadingConfigFile = func(configFile string, err error) error {
		return fmt.Errorf("reading config file (%s): %w", configFile, err)
	}
	ErrParsingConfigFile = func(configFile string, err error) error {
		return fmt.Errorf("parsing config file (%s): %w", configFile, err)
	}
)
