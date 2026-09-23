package detectors

import (
	"bytes"
	"coraldpi/util"
	"encoding/binary"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

func DetectTCP(pnum uint16, buf []byte) string {
	ret := ""
	for _, f := range checkFunctionsTCP {
		c := f(buf)
		if ret == "" {
			ret = c
		} else if c != "" {
			ret = ret + " !AND! " + c
		}
	}
	return ret
}

var checkFunctionsTCP = []func(buf []byte) (ret string){
	DetectPlains,
	DetectTLS,
}

func DetectTLS(buf []byte) (ret string) {
	if len(buf) < 10 {
		return
	}
	if buf[0] >= 0x14 && buf[0] <= 0x18 && buf[1] == 0x03 && buf[2] <= 5 && binary.BigEndian.Uint16(buf[3:5]) < 16384 {
		ret = "TLS " + []string{
			"ChangeCipherSpec",
			"Alert",
			"Handshake",
			"Application",
			"Heartbeat",
		}[buf[0]-0x14]
	}
	t := utls.Server(util.NewProvidedBytesConn(bytes.NewReader(buf)), &utls.Config{
		GetConfigForClient: func(hello *utls.ClientHelloInfo) (*utls.Config, error) {
			ret = "TLS ClientHello"
			if hello.ServerName != "" {
				ret += fmt.Sprintf(" SNI:%q", hello.ServerName)
			}
			return nil, net.ErrClosed
		},
	})
	t.Handshake()
	return
}

func DetectPlains(buf []byte) (ret string) {
	if len(buf) < 35 {
		return
	}
	if bytes.HasPrefix(buf, []byte("HTTP/")) {
		return util.PeekBytes(buf, 48)
	}
	if bytes.HasPrefix(buf, []byte("CONNECT ")) ||
		bytes.HasPrefix(buf, []byte("HEAD ")) ||
		bytes.HasPrefix(buf, []byte("OPTIONS ")) ||
		bytes.HasPrefix(buf, []byte("GET ")) ||
		bytes.HasPrefix(buf, []byte("POST ")) ||
		bytes.HasPrefix(buf, []byte("PUT ")) ||
		bytes.HasPrefix(buf, []byte("DELETE ")) ||
		bytes.HasPrefix(buf, []byte("PATCH ")) {
		// return "plain HTTP request"
		return util.PeekBytes(buf, 48)
	}
	if bytes.HasPrefix(buf, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		return "HTTP2 prior knowledge"
	}
	if bytes.HasPrefix(buf, []byte("+OK ")) {
		return "POP3"
	}
	if bytes.HasPrefix(buf, []byte("@RSYNCD: ")) {
		return "RSYNC s2c"
	}
	if bytes.HasPrefix(buf, []byte("SSH-")) {
		return "SSH banner"
	}
	return
}
