package common

import "net/http"

type ErrorHandler func(http.ResponseWriter, *http.Request) error

func (fn ErrorHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if err := fn(response, request); err != nil {
		CheckError(err, 2)
		http.Error(response, "Internal server error", http.StatusInternalServerError)
	}
}
