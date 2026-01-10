/*
go mod init example.com
go mod tidy
go run test.go
*/

package main

import (
	"os"

	imgs "github.com/k-atusa/USAG-Lib-macro/imgs"
)

func main() {
	var t imgs.Imgs
	data, _ := t.Zip_png()
	os.WriteFile("zip.png", data, 0644)
	data, _ = t.Zip_webp()
	os.WriteFile("zip.webp", data, 0644)
	data, _ = t.Aes_png()
	os.WriteFile("aes.png", data, 0644)
	data, _ = t.Aes_webp()
	os.WriteFile("aes.webp", data, 0644)
	data, _ = t.Cloud_png()
	os.WriteFile("cloud.png", data, 0644)
	data, _ = t.Cloud_webp()
	os.WriteFile("cloud.webp", data, 0644)
}
