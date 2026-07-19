// Note: inspiration for this from https://gist.github.com/cespare/3985516
package common

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
)

const (
	logFile = "access_log.txt"
)

type accessLog struct {
	ip, method, uri, protocol, host string
	elapsedTime                     time.Duration
}

func LogAccess(w http.ResponseWriter, req *http.Request, duration time.Duration) {
	clientIP := req.RemoteAddr

	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		clientIP = host
	}

	record := &accessLog{
		ip:          clientIP,
		method:      req.Method,
		uri:         req.URL.EscapedPath(),
		protocol:    req.Proto,
		host:        req.Host,
		elapsedTime: duration,
	}

	writeAccessLog(record)
}

func writeAccessLog(record *accessLog) {
	logRecord := sanitizeLogValue(record.ip) + " " + sanitizeLogValue(record.protocol) + " " + sanitizeLogValue(record.method) + ": " + sanitizeLogValue(record.uri) + ", host: " + sanitizeLogValue(record.host) + " (load time: " + strconv.FormatFloat(record.elapsedTime.Seconds(), 'f', 5, 64) + " seconds)"
	glog.Infoln(logRecord)
	glog.Flush()
}

func sanitizeLogValue(value string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(value)
}
