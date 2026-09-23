package util

import (
	"io"
	"net"
	"time"
)

type ProvidedBytesConn struct {
	r io.Reader
}

func NewProvidedBytesConn(r io.Reader) *ProvidedBytesConn {
	return &ProvidedBytesConn{r: r}
}

func (c *ProvidedBytesConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}
func (c *ProvidedBytesConn) Write(b []byte) (n int, err error) {
	return 0, net.ErrClosed
}
func (c *ProvidedBytesConn) Close() error {
	return nil
}
func (c *ProvidedBytesConn) LocalAddr() net.Addr {
	return nil
}
func (c *ProvidedBytesConn) RemoteAddr() net.Addr {
	return nil
}
func (c *ProvidedBytesConn) SetDeadline(t time.Time) error {
	return nil
}
func (c *ProvidedBytesConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (c *ProvidedBytesConn) SetWriteDeadline(t time.Time) error {
	return nil
}
