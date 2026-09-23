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
			return "DNS response no answers"
		}
		return fmt.Sprintf("DNS answers: %d", len(r))
	}
	q, err := p.AllQuestions()
	if err != nil {
		return ""
	}
	if len(q) == 0 {
		return "DNS query no questions"
	}
	ret := fmt.Sprintf("DNS query %q", q[0].Name)
	if len(q) > 1 {
		ret += " +" + strconv.Itoa(len(q))
	}
	return ret

}

func DetectTorrent(buf []byte) (ret string) {
	if len(buf) < 15 {
		return
	}
	if bytes.HasPrefix(buf, []byte("A\x00")) {
		return "probably torrent"
	}
	if bytes.HasPrefix(buf, []byte("!\x00")) {
		return "probably torrent"
	}
	if bytes.HasPrefix(buf, []byte("\x01\x00")) {
		return "probably torrent"
	}
	if bytes.HasPrefix(buf, []byte("d1:")) {
		return "probably torrent"
	}
	return
}
