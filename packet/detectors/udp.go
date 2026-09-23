package detectors

import (
	"fmt"
	"strconv"

	"golang.org/x/net/dns/dnsmessage"
)

func DetectUDP(port uint16, data []byte) string {
	// if len(data) < 14 {
	// 	return ""
	// }
	return DetectDNS(data)
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
