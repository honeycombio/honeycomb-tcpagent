package common

import "fmt"

// NewSafeBuffer tries to allocate a buffer of size bufsize. If bufsize is
// negative or greater than maxsize, it returns an error. Use this function
// when allocating based on buffer lengths in TCP data; otherwise bad packets
// may cause crashes.
func NewSafeBuffer(bufsize int, maxsize int) ([]byte, error) {
	if (bufsize < 0) || (bufsize > maxsize) {
		return nil, fmt.Errorf("Invalid buffer size %d", bufsize)
	}
	return make([]byte, bufsize), nil
}
