package util

import (
	"fmt"
	"strconv"
)

func ToEscapedHex(buf []byte) string {
	ret := ""
	for _, c := range buf {
		if c >= 0x20 && c <= 0x7e {
			ret += string(c)
			continue
		}
		if c == 0x0 {
			ret += `\0`
			continue
		}
		if c == 0x9 {
			ret += `\t`
			continue
		}
		if c == 0xa {
			ret += `\n`
			continue
		}
		if c == 0xd {
			ret += `\r`
			continue
		}
		if c > 0xf {
			ret += `\x` + strconv.FormatUint(uint64(c), 16)
		} else {
			ret += `\x0` + strconv.FormatUint(uint64(c), 16)
		}
	}
	return ret
}

func PeekBytes(buf []byte, maxlen int) string {
	if len(buf) == 0 {
		return "0 bytes"
	}
	repeats := 1
	prev := buf[0]
	for _, b := range buf[1:] {
		if b == prev {
			repeats++
		} else {
			prev = b
		}
	}
	if repeats == len(buf) {
		return fmt.Sprintf("%d 0x%02x", len(buf), buf[0])
	}
	return fmt.Sprintf("%q", buf[:min(len(buf), maxlen)])
}
