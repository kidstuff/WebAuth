package auth

import (
	"net/http"
	"strings"
)

func BadRequestHanlder(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(http.StatusBadRequest)
	rw.Write([]byte("{error:\"Badd Request\"}"))
}

func ForbiddenHanlder(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(http.StatusForbidden)
	rw.Write([]byte("{error:\"" + ErrNotLogged.Error() + "\"}"))
}

func InternalServerErrorHanlder(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(http.StatusForbidden)
	rw.Write([]byte("{error:\"Internal Server Error\"}"))
}

func OAuthHandleWrapper(handler http.HandlerFunc,
	pri map[string]bool) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		userMngr, err := Provider().OpenUserMngr()
		if err != nil {
			InternalServerErrorHanlder(rw, req)
		}
		defer userMngr.Close()

		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		user, err := userMngr.GetUser(token)
		if err != nil {
			if err == ErrNotLogged {
				ForbiddenHanlder(rw, req)
				return
			}
			InternalServerErrorHanlder(rw, req)
			return
		}

		for key, val := range pri {
			if val {
				if !userMngr.Can(user, key) {
					ForbiddenHanlder(rw, req)
					return
				}
			}
		}

		// run user defined handler
		handler(rw, req)
	}
}
