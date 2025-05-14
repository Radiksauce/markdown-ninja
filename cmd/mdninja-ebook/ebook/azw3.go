package ebook

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func ConvertEpubToAzw3(ctx context.Context, distPath, epubPath string, coverPath, workingDir *string) (err error) {
	if !strings.HasSuffix(epubPath, ".epub") {
		err = fmt.Errorf("input file (%s) must ends with .epub", epubPath)
		return
	}

	cmdArgs := []string{epubPath, distPath}
	if coverPath != nil {
		cmdArgs = append(cmdArgs, "--cover", *coverPath)
	}
	cmd := exec.CommandContext(ctx, "ebook-convert", cmdArgs...)

	cmd.Env = ebooksSandboxEnv()
	if workingDir != nil {
		cmd.Dir = *workingDir
	}
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		output := string(cmdOutput)
		err = fmt.Errorf("ebookToAzw3: %w -> %s", err, output)
		return
	}

	return
}
