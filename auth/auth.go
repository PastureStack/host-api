package auth

import (
	"net/http"
	"time"

	"github.com/PastureStack/host-api/app/common"
	"github.com/PastureStack/host-api/config"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/golang/glog"
)

func Auth(rw http.ResponseWriter, req *http.Request) bool {
	if !config.Config.Auth {
		return true
	}
	tokenString := req.URL.Query().Get("token")

	if len(tokenString) == 0 {
		return false
	}

	token, err := ParseToken(tokenString, config.Config.ParsedPublicKey)
	if err != nil {
		glog.Warning("Token validation failed")
		return false
	}

	if !token.Valid {
		return false
	}
	if config.Config.HostUuidCheck {
		hostUUID, found := GetClaimString(token, "hostUuid")
		if !found || hostUUID != config.Config.HostUuid {
			glog.Infoln("Host UUID mismatch , authentication failed")
			return false
		}
	}
	SetToken(req, token)

	return true
}

func GetAndCheckToken(tokenString string) (*jwt.Token, bool) {
	token, err := ParseToken(tokenString, config.Config.ParsedPublicKey)
	if err != nil {
		glog.Warning("Token validation failed")
		return token, false
	}

	if !token.Valid {
		return token, false
	}

	if config.Config.HostUuidCheck {
		hostUUID, found := GetClaimString(token, "hostUuid")
		if !found || hostUUID != config.Config.HostUuid {
			glog.Infoln("Host UUID mismatch , authentication failed")
			return token, false
		}
	}

	return token, true

}

func AuthHttpInterceptor(router http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		startTime := time.Now()

		if !Auth(w, req) {
			http.Error(w, "Failed authentication", 401)
			return
		}

		router.ServeHTTP(w, req)

		finishTime := time.Now()
		elapsedTime := finishTime.Sub(startTime)

		switch req.Method {
		case "GET":
			// We may not always want to StatusOK, but for the sake of
			// this example we will
			common.LogAccess(w, req, elapsedTime)
		case "POST":
			// here we might use http.StatusCreated
		}

	})
}
