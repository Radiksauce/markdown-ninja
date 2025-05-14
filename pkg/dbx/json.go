package dbx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type Json[D any] struct {
	Val D `db:"value"`
}

func (record *Json[D]) Scan(val any) error {
	switch v := val.(type) {
	case []byte:
		json.Unmarshal(v, &record.Val)
		return nil
	case string:
		json.Unmarshal([]byte(v), &record.Val)
		return nil
	default:
		return fmt.Errorf("Json.Scan: Unsupported type: %T", v)
	}
}

func (record Json[D]) Value() (driver.Value, error) {
	return json.Marshal(record.Val)
}
