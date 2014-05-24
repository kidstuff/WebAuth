package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

const (
	ErrCodeUnknown   int = 0
	ErrCodeNotLogged     = 1
)

// JSONErr returned to the user an informative error json message
type JSONErr struct {
	Code        int
	Message     string
	Description string    `json:",omitempty"`
	StackStrace string    `json:",omitempty"`
	Errors      []JSONErr `json:",omitempty"`
}

func errHandler(rw http.ResponseWriter, sttCode int, err *JSONErr) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(sttCode)
	json.NewEncoder(rw).Encode(err)
}

func BadRequestHanlder(rw http.ResponseWriter, err *JSONErr) {
	errHandler(rw, http.StatusBadRequest, err)
}

func ForbiddenHanlder(rw http.ResponseWriter, err *JSONErr) {
	errHandler(rw, http.StatusForbidden, err)
}

func InternalServerErrorHandler(rw http.ResponseWriter, err *JSONErr) {
	errHandler(rw, http.StatusInternalServerError, err)
}

func OAuthHandleWrapper(handler http.HandlerFunc, pri ...string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		userMngr, err := Provider().OpenUserMngr()
		if err != nil {
			InternalServerErrorHandler(rw, &JSONErr{Message: err.Error()})
		}
		defer userMngr.Close()

		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		user, err := userMngr.GetUser(token)
		if err != nil {
			if err == ErrNotLogged {
				ForbiddenHanlder(rw, &JSONErr{
					Code:        ErrCodeNotLogged,
					Message:     err.Error(),
					Description: "User need to be logged in to perform this action.",
				})
				return
			}
			InternalServerErrorHandler(rw, &JSONErr{Message: err.Error()})
			return
		}

		var (
			cannot   bool
			cannotDo string
		)
		for _, do := range pri {
			if !userMngr.Can(user, do) {
				cannotDo += do + ","
			}
		}

		if cannot {
			ForbiddenHanlder(rw, &JSONErr{
				Code:        2,
				Message:     "User doesn't have valid permission.",
				Description: "User doesn't have " + cannotDo + " permission.",
			})
			return
		}

		// run user defined handler
		handler(rw, req)
	}
}
