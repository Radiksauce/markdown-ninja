package migrations

import (
	"embed"
)

//go:embed **/*.sql
var MigrationsFs embed.FS

// type DatabasesMigrations struct {
// 	MarkdownNinja []db.Migration
// 	// MarkdownNinjaEvents []migrate.Migration
// }

// func Migrations() (ret []db.Migration, err error) {
// 	ret, err = loadMigrations("markdown_ninja")
// 	if err != nil {
// 		return
// 	}

// 	return
// }

// func loadMigrations(directory string) (migrations []db.Migration, err error) {
// 	migrations = make([]db.Migration, 0)

// 	directoryEntries, err := migrationsFs.ReadDir(directory)
// 	if err != nil {
// 		err = fmt.Errorf("migrations: error reading directory: %w", err)
// 		return
// 	}

// 	var upFiles = make([]string, 0, len(directoryEntries))
// 	var downFiles = make([]string, 0, len(directoryEntries))

// 	for _, directoryEntry := range directoryEntries {
// 		fileName := directoryEntry.Name()
// 		if directoryEntry.Type().IsRegular() {
// 			if strings.HasSuffix(fileName, ".up.sql") {
// 				upFiles = append(upFiles, fileName)
// 			} else if strings.HasSuffix(fileName, ".down.sql") {
// 				downFiles = append(downFiles, fileName)
// 			} else {
// 				err = fmt.Errorf("migrations: File is neither a .up.sql nor a .down.sql: %s", fileName)
// 				return
// 			}
// 		}
// 	}

// 	if len(upFiles) != len(downFiles) {
// 		err = errors.New("migrations: each .up.sql file should have a corresponding .down.sql file")
// 		return
// 	}

// 	sort.Strings(upFiles)
// 	sort.Strings(downFiles)

// 	migrations = make([]db.Migration, len(upFiles))
// 	for i, upFile := range upFiles {
// 		downFile := downFiles[i]
// 		var upFileContent []byte
// 		var downFileContent []byte

// 		upParts := strings.Split(upFile, ".")
// 		downParts := strings.Split(upFile, ".")
// 		if len(upParts) != 3 || len(upParts) != len(downParts) ||
// 			upParts[0] != downParts[0] {
// 			err = fmt.Errorf("migrations: up file \"%s\" has no corresponding down file", upFile)
// 			return
// 		}

// 		upFileContent, err = migrationsFs.ReadFile(filepath.Join(directory, upFile))
// 		if err != nil {
// 			err = fmt.Errorf("migrations: error reading file \"%s\": %w", upFile, err)
// 			return
// 		}

// 		downFileContent, err = migrationsFs.ReadFile(filepath.Join(directory, downFile))
// 		if err != nil {
// 			err = fmt.Errorf("migrations: error reading file \"%s\": %w", upFile, err)
// 			return
// 		}

// 		migrations[i] = db.Migration{
// 			ID:   int64(i),
// 			Name: strings.TrimSuffix(upFile, ".up.sql"),
// 			Up: func(ctx context.Context, tx db.Queryer) (err error) {
// 				_, err = tx.Exec(ctx, string(upFileContent))
// 				return
// 			},
// 			Down: func(ctx context.Context, tx db.Queryer) (err error) {
// 				_, err = tx.Exec(ctx, string(downFileContent))
// 				return
// 			},
// 		}
// 	}

// 	return
// }
