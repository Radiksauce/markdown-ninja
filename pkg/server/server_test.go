package server_test

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"testing"

	"github.com/klauspost/compress/zstd"
	"markdown.ninja/pkg/services/site/templates"
)

func BenchmarkCompressHtml(b *testing.B) {
	levels := []zstd.EncoderLevel{
		zstd.SpeedFastest,
		zstd.SpeedDefault,
		zstd.SpeedBetterCompression,
		zstd.SpeedBestCompression,
	}

	inputData := bytes.NewBuffer(make([]byte, 0, 50_000))
	for range 5 {
		inputData.Write([]byte(templates.LoginEmailTemplate))
	}
	inputDataReader := bytes.NewReader(inputData.Bytes())
	outputBuffer := bytes.NewBuffer(make([]byte, 0, inputData.Len()))

	for _, compressionLevel := range levels {

		b.Run(fmt.Sprintf("zstd-%s", compressionLevel.String()), func(b *testing.B) {
			runtime.GC()
			b.ReportAllocs()
			b.SetBytes(int64(inputData.Len()))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				inputDataReader.Seek(0, io.SeekStart)
				outputBuffer.Reset()
				zstdEncoder, err := zstd.NewWriter(outputBuffer, zstd.WithEncoderCRC(true), zstd.WithEncoderLevel(zstd.SpeedDefault))
				if err != nil {
					b.Error(err)
				}
				io.Copy(zstdEncoder, inputDataReader)
				err = zstdEncoder.Close()
				if err != nil {
					b.Error(err)
				}
			}
		})

	}

}
