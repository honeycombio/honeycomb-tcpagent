package publish

import (
	"io"
	"os"
)

func Publish(s []byte) {
	io.WriteString(os.Stdout, string(s))
	io.WriteString(os.Stdout, "\n")
}
