package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// GitCommit is set at build time
var gitCommit string

// Version is the version of the program. Set at build time
var Version string

var goVersion string

const (
	// OS is the OS the program is run on
	OS = runtime.GOOS
	// Arch is the processor architecture the program is run on
	Arch = runtime.GOARCH
	// Name is the name of the program
	Name = "mdninja"

	GoModule = "markdown.ninja"
)

// GoVersion is the go version used to compile the program, set at build time
func GoVersion() string {
	if goVersion == "" {
		if info, buildInfoOk := debug.ReadBuildInfo(); buildInfoOk {
			goVersion = info.GoVersion
		}
	}

	return goVersion
}

func GitCommit() string {
	if gitCommit == "" {
		if info, buildInfoOk := debug.ReadBuildInfo(); buildInfoOk {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" {
					gitCommit = setting.Value
				}
			}
		}
	}

	return gitCommit
}
