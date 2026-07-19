package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/common"
)

type Handler struct {
}

const maxInitialProxyMessageBytes = 1 << 20

func (s *Handler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	defer backend.SignalHandlerClosed(key, response)
	logger := log.WithField("handler", "container-proxy")

	message, err := readMessage(incomingMessages)
	if err != nil {
		logger.WithField("error", err).Error("Invalid proxy content")
		return
	}

	logger.WithFields(log.Fields{"key": key, "method": message.Method}).Debug("Starting proxied request")

	if message.Hijack {
		s.doHijack(message, key, incomingMessages, response)
	} else {
		s.doHttp(message, key, incomingMessages, response)
	}
}

func (s *Handler) doHijack(message *common.HTTPMessage, key string, incomingMessages <-chan string, response chan<- common.Message) {
	req, err := http.NewRequest(message.Method, message.URL, nil)
	if err != nil {
		log.Error("Failed to create hijacked proxy request")
		return
	}
	req.Host = message.Host
	req.Header = http.Header(message.Headers)

	if req.Header.Get("Connection") != "Upgrade" {
		req.Header.Set("Connection", "close")
	}

	content, err := setContentLength(req)
	if err != nil {
		return
	}

	u := req.URL
	if err := validateTargetURL(u); err != nil {
		log.WithField("error", err).Error("Rejected proxy target")
		return
	}
	if content > maxInitialProxyMessageBytes {
		log.WithField("contentLength", content).Error("Hijacked request body is too large")
		return
	}

	conn, err := dialProxyTarget(u)
	if err != nil {
		log.WithField("error", err).Errorf("Failed to connect to %s", u.Host)
		return
	}
	defer conn.Close()

	reader := &HttpReader{
		Buffered:   message.Body,
		Chan:       incomingMessages,
		EOF:        message.EOF,
		MessageKey: key,
	}

	writer := &HttpWriter{
		MessageKey: key,
		Chan:       response,
	}

	if content > 0 {
		buf := make([]byte, int(content))
		if _, err := io.ReadFull(reader, buf); err != nil {
			log.WithField("error", err).Errorf("Failed to read initial content for %s", u.Host)
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(buf))
	}

	if err := req.Write(conn); err != nil {
		log.WithField("target", proxyLogTarget(u)).Error("Failed to write hijacked proxy request")
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(conn, reader); err != nil {
			log.WithField("target", proxyLogTarget(u)).Error("Failed to stream hijacked proxy request")
		}
		reader.Close()

		for range incomingMessages {
			// waiting for channel to close
		}
		conn.Close()
	}()

	if _, err := io.Copy(writer, conn); err != nil {
		log.WithField("target", proxyLogTarget(u)).Info("Hijacked proxy response stream closed")
	}
	writer.Close()

	wg.Wait()
}

func dialProxyTarget(target *url.URL) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	address := proxyTargetAddress(target)
	if target.Scheme == "https" {
		return tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: target.Hostname(),
		})
	}
	return dialer.Dial("tcp", address)
}

func proxyTargetAddress(target *url.URL) string {
	if target.Port() != "" {
		return target.Host
	}
	port := "80"
	if target.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(target.Hostname(), port)
}

func setContentLength(req *http.Request) (int64, error) {
	if lengthString := req.Header.Get("Content-Length"); lengthString != "" {
		length, err := strconv.ParseInt(lengthString, 10, 64)
		if err != nil {
			log.Error("Invalid proxy content length")
			return 0, err
		}
		if length < 0 {
			return 0, errors.New("content length must not be negative")
		}
		req.ContentLength = length
	}
	return req.ContentLength, nil
}

func (s *Handler) doHttp(message *common.HTTPMessage, key string, incomingMessages <-chan string, response chan<- common.Message) {
	req, err := http.NewRequest(message.Method, message.URL, &HttpReader{
		Buffered:   message.Body,
		Chan:       incomingMessages,
		EOF:        message.EOF,
		MessageKey: key,
	})
	if err != nil {
		log.Error("Failed to create proxy request")
		return
	}
	if err := validateTargetURL(req.URL); err != nil {
		log.WithField("error", err).Error("Rejected proxy target")
		return
	}
	req.Host = message.Host
	req.Header = http.Header(message.Headers)

	if _, err := setContentLength(req); err != nil {
		return
	}

	transport := &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  60 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 1 << 20,
	}
	client := http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.WithField("target", proxyLogTarget(req.URL)).Error("Failed to make proxy request")
		return
	}
	defer resp.Body.Close()

	httpResponseMessage := common.HTTPMessage{
		Code:    resp.StatusCode,
		Headers: map[string][]string(resp.Header),
	}

	httpWriter := &HttpWriter{
		Message:    httpResponseMessage,
		MessageKey: key,
		Chan:       response,
	}
	defer httpWriter.Close()

	// Make sure we write the response codes if the response buffer is 0 bytes but blocking.
	// This happens with streaming logs a log
	if err := httpWriter.writeMessage(); err != nil {
		log.WithField("error", err).Error("Failed to write header")
		return
	}

	if _, err := io.Copy(httpWriter, resp.Body); err != nil {
		log.WithField("error", err).Error("Failed to write body")
		return
	}
}

func readMessage(incomingMessages <-chan string) (*common.HTTPMessage, error) {
	str, ok := <-incomingMessages
	if !ok {
		return nil, io.EOF
	}
	if len(str) > maxInitialProxyMessageBytes {
		return nil, fmt.Errorf("proxy metadata exceeds %d bytes", maxInitialProxyMessageBytes)
	}
	var message common.HTTPMessage
	if err := json.Unmarshal([]byte(str), &message); err != nil {
		return nil, err
	}
	return &message, nil
}

func validateTargetURL(target *url.URL) error {
	if target == nil || target.Host == "" {
		return errors.New("proxy target host is required")
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return fmt.Errorf("unsupported proxy target scheme %q", target.Scheme)
	}
	if target.User != nil {
		return errors.New("proxy target user information is not allowed")
	}
	if target.Fragment != "" {
		return errors.New("proxy target fragment is not allowed")
	}
	return nil
}

func proxyLogTarget(target *url.URL) string {
	if target == nil {
		return "<invalid>"
	}
	redacted := *target
	redacted.User = nil
	redacted.RawQuery = ""
	redacted.Fragment = ""
	return redacted.String()
}
