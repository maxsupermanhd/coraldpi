package main

import (
	"coraldpi/packet/analyser"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
)

var captureDeviceName = flag.String("d", "enp12s0", "device/interface to cpature")

func main() {
	flag.Parse()
	// device := "br-lan"
	// device := "enp12s0"
	device := *captureDeviceName

	signalChan := make(chan os.Signal, 3)
	ia := analyser.NewInterfaceAnalyser()

	exitChan := make(chan struct{})
	var wg sync.WaitGroup

	wg.Go(func() {
		fmt.Println("starting capture on interface", device)
		err := ia.Capture(device, exitChan)
		if err != nil {
			fmt.Println("capture exited with: ", err)
		}
		close(signalChan)
	})
	wg.Go(func() {
		var memStats runtime.MemStats
		for {
			select {
			case <-time.After(5 * time.Second):
				fmt.Println("\n\n")
				st := ia.GetStats()
				for _, c := range st.Convs {
					fmt.Println(c)
				}
				byL2 := ""
				for _, k := range slices.Sorted(maps.Keys(st.PkCountL2)) {
					byL2 += strconv.FormatUint(uint64(k), 16) + ":" + strconv.Itoa(st.PkCountL2[k]) + " "
				}
				byL3 := ""
				for _, k := range slices.Sorted(maps.Keys(st.PkCountL3)) {
					byL3 += strconv.FormatUint(uint64(k), 16) + ":" + strconv.Itoa(st.PkCountL3[k]) + " "
				}
				byL4 := ""
				for _, k := range slices.Sorted(maps.Keys(st.PkCountL4)) {
					byL4 += k + ":" + strconv.Itoa(st.PkCountL4[k]) + " "
				}
				fmt.Println("captured", st.FramesCapturedTotal, "dropped", st.FramesDroppedTotal)
				fmt.Println("by L2", byL2)
				fmt.Println("by L3", byL3)
				fmt.Println("by L4", byL4)
				// for _, c := range slices.Sorted(slices.Values(st.Conns)) {
				// 	fmt.Println(c)
				// }
				// fmt.Println("open", st.TCPConnsOpen, "closed", st.TCPConnsClosed, byL4)
				runtime.ReadMemStats(&memStats)
				fmt.Println("memory allocated", humanize.Bytes(memStats.Sys))
				if memStats.Sys > 1_000_000_000 {
					fmt.Println("too much allocated, exiting")
					os.Exit(1)
				}
			case <-exitChan:
				return
			}
		}
	})

	signal.Notify(signalChan, os.Interrupt)

	<-signalChan
	fmt.Println("exiting")
	close(exitChan)

	wg.Wait()

	fmt.Println("done")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func noerr[T any](ret T, err error) T {
	must(err)
	return ret
}

func noerr2[T, T2 any](ret T, ret2 T2, err error) (T, T2) {
	must(err)
	return ret, ret2
}
