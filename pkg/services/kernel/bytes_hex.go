package kernel

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// BytesHex is a simple []byte that encodes to hexadecimal when marshaling to JSONs
type BytesHex []byte

var bytesHexNUll = []byte("null")

func (b BytesHex) String() string {
	return hex.EncodeToString(b)
}

func (b BytesHex) MarshalJSON() ([]byte, error) {
	if b == nil {
		return bytesHexNUll, nil
	}

	buffer := bytes.NewBuffer(make([]byte, 0, (2 + len(b)*2)))
	buffer.WriteRune('"')
	buffer.WriteString(hex.EncodeToString(b))
	buffer.WriteRune('"')
	return buffer.Bytes(), nil
}

func (b *BytesHex) UnmarshalJSON(data []byte) (err error) {
	if data == nil || bytes.Equal(data, bytesHexNUll) {
		return nil
	}

	data = bytes.Trim(data, `"`)
	decodedData, err := hex.DecodeString(string(data))
	if err != nil {
		return
	}

	*b = decodedData
	return nil
}

func (b *BytesHex) Scan(val any) error {
	switch v := val.(type) {
	case []byte:
		*b = v
		return nil
	case nil:
		return nil
	default:
		return fmt.Errorf("BytesHex.Scan: Unsupported type: %T", v)
	}
}
