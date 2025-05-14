package ebook

import (
	"context"
	"fmt"
	"os/exec"
)

func ebookToEpub(ctx context.Context, config Config, pandocFiles pandocFiles, distPath string) (err error) {
	args := []string{pandocFiles.settingsPath}
	args = append(args, config.Chapters...)
	args = append(args, "--output="+distPath)
	args = append(args, "--table-of-contents")
	args = append(args, "--toc-depth=2")
	args = append(args, "--top-level-division=chapter")
	args = append(args, "--number-sections")
	args = append(args, "--listings")
	args = append(args, "--standalone")
	args = append(args, "--strip-comments")
	args = append(args, "--epub-cover-image="+config.Cover)
	args = append(args, "--metadata", "title="+config.Title)
	args = append(args, "--highlight-style="+pandocFiles.themePath)
	args = append(args, "--css="+pandocFiles.epubCssPath)
	args = append(args, "-M", "date="+config.Version)
	// not sure if documentclass=book is needed for EPub...
	args = append(args, "-V", "documentclass=book")
	// --reference-location=document puts the references at the end of the chapter :)
	args = append(args, "--reference-location=document")
	// if we use the --file-scope flag, footnotes/references can't be consigned in a different file
	// (references.md for example). On the other hand, it forces footnotes to be globally uniques as they
	// will all share the same scope
	// args = append(args, "--file-scope")
	// args = append(args, "--reference-links")            // not working...

	cmd := exec.CommandContext(ctx, "pandoc", args...)
	cmd.Env = ebooksSandboxEnv()
	cmd.Dir = config.tmpWorkingDir
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		output := string(cmdOutput)
		err = fmt.Errorf("ebookToEpub: creating epub: %w -> %s", err, output)
		return
	}

	// TODO
	// cmd = exec.Command("java", "-jar", "/usr/bin/epubcheck", m.config.distFileEpub)
	// cmdOutput, err = cmd.CombinedOutput()
	// if err != nil {
	// 	output = string(cmdOutput)
	// 	err = fmt.Errorf("md2epub: checking epub %w", err)
	// 	return
	// }

	return
}
