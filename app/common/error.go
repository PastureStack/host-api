package common

import (
	"log"
	"runtime"

	"github.com/golang/glog"
)

// 0 = info
// 1 = warning
// 2 = error - should be most common
// 3 = fatal
func CheckError(err error, level int) {
	if err != nil {
		var stack [4096]byte
		length := runtime.Stack(stack[:], false)
		trace := stack[:length]
		log.Printf("%q\n%s\n", err, trace)

		switch level {
		case 0:
			glog.Infof("%q\n%s\n", err, trace)
		case 1:
			glog.Warningf("%q\n%s\n", err, trace)
		case 2:
			glog.Errorf("%q\n%s\n", err, trace)
		case 3:
			glog.Fatalf("%q\n%s\n", err, trace)
		}

		glog.Flush()
	}
}
