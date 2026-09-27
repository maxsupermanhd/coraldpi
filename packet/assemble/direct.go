package assemble

import "github.com/google/gopacket"

const DirectAppendAssemblerBufSize = 512

type directAppendAssembler struct {
	have int
	buf  [DirectAppendAssemblerBufSize]byte
}

func NewDirectAppendAssembler() *directAppendAssembler {
	return &directAppendAssembler{buf: [DirectAppendAssemblerBufSize]byte{}}
}

func (a *directAppendAssembler) Peek() []byte {
	return a.buf[:a.have]
}

func (a *directAppendAssembler) Feed(pk gopacket.Layer) {
	b := pk.LayerPayload()
	if len(b) == 0 {
		return
	}
	a.have += copy(a.buf[a.have:], b)
	return
}

func (a *directAppendAssembler) Reset() {
	a.have = 0
}
