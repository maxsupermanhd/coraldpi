package detectors

import (
	"bytes"
	"fmt"
	"strconv"

	"golang.org/x/net/dns/dnsmessage"
)

func DetectUDP(pnum uint16, buf []byte) string {
	ret := ""
	for _, f := range checkFunctionsUDP {
		c := f(buf)
		if ret == "" {
			ret = c
		} else if c != "" {
			ret = ret + " !AND! " + c
		}
	}
	return ret
}

var checkFunctionsUDP = []func(buf []byte) (ret string){
	DetectDNS,
	DetectTorrent,
}

func DetectDNS(data []byte) string {
	p := &dnsmessage.Parser{}
	h, err := p.Start(data)
	if err != nil {
		return ""
	}
	if h.Response {
		err := p.SkipAllQuestions()
		if err != nil {
			return ""
		}
		r, err := p.AllAnswers()
		if err != nil {
			return ""
		}
		if len(r) == 0 {
			return "DNS: response without answers"
		}
		return fmt.Sprintf("DNS answers: %d", len(r))
	}
	q, err := p.AllQuestions()
	if err != nil {
		return ""
	}
	if len(q) == 0 {
		return "DNS: query without questions"
	}
	ret := fmt.Sprintf("DNS: query %q", q[0].Name)
	if len(q) > 1 {
		ret += " +" + strconv.Itoa(len(q))
	}
	return ret

}

func DetectTorrent(buf []byte) (ret string) {
	if len(buf) < 20 {
		return
	}
	if string(buf[:12]) == string([]byte{0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, 0x00, 0x00, 0x00, 0x00}) {
		return "Torrent: Tracker connect request"
	}
	if buf[0] == 'd' &&
		bytes.Contains(buf, []byte("1:y1:q")) &&
		bytes.Contains(buf, []byte("1:q")) {
		return "Torrent: DHT query"
	}
	return
}
