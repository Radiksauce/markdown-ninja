package ebook

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"markdown.ninja/cmd/mdninja-ebook/pandoc"
)

type pandocFiles struct {
	settingsPath      string
	inlineCodeTexPath string
	themePath         string
	epubCssPath       string
}

func generatePandocFiles(config Config, pandocTmpDir string) (pandocFiles pandocFiles, err error) {
	configFilePermission := os.FileMode(0644)

	pandocFiles.settingsPath = filepath.Join(pandocTmpDir, "pandoc_settings.txt")
	pandocSettingsTemplate, err := template.New("pandoc.settings").Parse(string(pandoc.SettingsTemplate))
	if err != nil {
		err = fmt.Errorf("error parsing pandoc settings template: %w", err)
		return
	}

	var pandocSettingsBuffer bytes.Buffer
	pandocSettingsData := pandoc.SettingsTemplateData{
		Title:      config.Title,
		Subtitle:   config.Subtitle,
		Author:     config.Author,
		Cover:      config.Cover,
		Tags:       config.Tags,
		Identifier: config.BookID,
	}
	err = pandocSettingsTemplate.Execute(&pandocSettingsBuffer, pandocSettingsData)
	if err != nil {
		err = fmt.Errorf("error executing template for pandoc settings: %w", err)
		return
	}
	err = os.WriteFile(pandocFiles.settingsPath, pandocSettingsBuffer.Bytes(), configFilePermission)
	if err != nil {
		err = fmt.Errorf("error writing pandoc settings file (%s): %w", pandocFiles.settingsPath, err)
		return
	}

	pandocFiles.inlineCodeTexPath = filepath.Join(pandocTmpDir, "inline_code.tex")
	err = os.WriteFile(pandocFiles.inlineCodeTexPath, pandoc.InlineCodeTex, configFilePermission)
	if err != nil {
		err = fmt.Errorf("error writing pandoc inline code tex file (%s): %w", pandocFiles.inlineCodeTexPath, err)
		return
	}

	// it's important that the file has a .theme extension otherwise pandoc will not recognize it
	pandocFiles.themePath = filepath.Join(pandocTmpDir, "tango_modified.theme")
	err = os.WriteFile(pandocFiles.themePath, pandoc.ThemeTango, configFilePermission)
	if err != nil {
		err = fmt.Errorf("error writing pandoc theme (%s): %w", pandocFiles.themePath, err)
		return
	}

	pandocFiles.epubCssPath = filepath.Join(pandocTmpDir, "pandoc_epub.css")
	err = os.WriteFile(pandocFiles.epubCssPath, pandoc.EpubCss, configFilePermission)
	if err != nil {
		err = fmt.Errorf("error writing pandoc epub.css file (%s): %w", pandocFiles.epubCssPath, err)
		return
	}

	return
}
