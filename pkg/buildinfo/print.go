package buildinfo

import (
	"encoding/json"
	"fmt"
)

type buildInfoJSON struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	GitCommit    string `json:"gitCommit"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	GoVersion    string `json:"goVersion"`
}

func PrintText() {
	fmt.Printf("Name           : %s\n", Name)
	fmt.Printf("Version        : %s\n", Version)
	fmt.Printf("Git commit     : %s\n", GitCommit())
	fmt.Printf("OS             : %s\n", OS)
	fmt.Printf("Architecture   : %s\n", Arch)
	fmt.Printf("Go version     : %s\n", GoVersion())
}

func PrintJSON() error {
	var err error
	var output []byte

	jsonVersion := buildInfoJSON{
		Name:         Name,
		Version:      Version,
		GitCommit:    GitCommit(),
		OS:           OS,
		Architecture: Arch,
		GoVersion:    GoVersion(),
	}
	output, err = json.Marshal(&jsonVersion)
	if err == nil {
		fmt.Println(string(output))
	}
	return err
}
