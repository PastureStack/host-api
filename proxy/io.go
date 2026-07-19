package proxy

import (
	"encoding/json"
	"io"

	"github.com/PastureStack/websocket-proxy/common"
	"github.com/sirupsen/logrus"
)

type HttpWriter struct {
	headerWritten bool
	Message       common.HTTPMessage
	MessageKey    string
	Chan          chan<- common.Message
}

func (h *HttpWriter) Write(bytes []byte) (n int, err error) {
	h.Message.Body = bytes
	if err := h.writeMessage(); err != nil {
		return 0, err
	}
	return len(bytes), nil
}

func (h *HttpWriter) writeMessage() error {
	bytes, err := json.Marshal(&h.Message)
	if err != nil {
		return err
	}
	m := common.Message{
		Key:  h.MessageKey,
		Type: common.Body,
		Body: string(bytes),
	}
	logrus.WithFields(logrus.Fields{"key": h.MessageKey, "bytes": len(m.Body)}).Debug("HTTP proxy response chunk")
	h.Chan <- m
	h.Message = common.HTTPMessage{}
	return nil
}

func (h *HttpWriter) Close() error {
	h.Message.EOF = true
	return h.writeMessage()
}

type HttpReader struct {
	Buffered   []byte
	Chan       <-chan string
	EOF        bool
	MessageKey string
}

func (h *HttpReader) Close() error {
	logrus.Debugf("HTTP READER CLOSE %s", h.MessageKey)
	return nil
}

func (h *HttpReader) Read(bytes []byte) (int, error) {
	if len(h.Buffered) == 0 && !h.EOF {
		if err := h.read(); err != nil {
			return 0, err
		}
	}

	count := copy(bytes, h.Buffered)
	h.Buffered = h.Buffered[count:]

	if h.EOF {
		logrus.Debugf("HTTP READER RETURN EOF %s", h.MessageKey)
		return count, io.EOF
	} else {
		logrus.WithFields(logrus.Fields{"key": h.MessageKey, "bytes": count, "buffered": len(h.Buffered)}).Debug("HTTP proxy request chunk")
		return count, nil
	}
}

func (h *HttpReader) read() error {
	str, ok := <-h.Chan
	if !ok {
		logrus.Debugf("HTTP READER CHANNEL EOF %s", h.MessageKey)
		return io.EOF
	}

	var message common.HTTPMessage
	if err := json.Unmarshal([]byte(str), &message); err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{"key": h.MessageKey, "bytes": len(message.Body)}).Debug("HTTP proxy request message")

	h.Buffered = message.Body
	h.EOF = message.EOF
	return nil
}
