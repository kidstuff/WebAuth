package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

const (
	ErrCodeUnknown   float32 = 0.0
	ErrCodeNotLogged float32 = 0.1
)

// JSONErr returned to the user an informative error json message
type JSONErr struct {
	Code        float32
	Message     string
	Description string    `json:",omitempty"`
	StackStrace string    `json:",omitempty"`
	Errors      []JSONErr `json:",omitempty"`
}

func ErrorResponse(rw http.ResponseWriter, sttCode int, err *JSONErr) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(sttCode)
	json.NewEncoder(rw).Encode(err)
}

func BadRequestResponse(rw http.ResponseWriter, err *JSONErr) {
	ErrorResponse(rw, http.StatusBadRequest, err)
}

func ForbiddenResponse(rw http.ResponseWriter, err *JSONErr) {
	ErrorResponse(rw, http.StatusForbidden, err)
}

func InternalErrorResponse(rw http.ResponseWriter, err *JSONErr) {
	ErrorResponse(rw, http.StatusInternalServerError, err)
}

func UnauthorizedResponse(rw http.ResponseWriter, err *JSONErr) {
	ErrorResponse(rw, http.StatusUnauthorized, err)
}

func OAuthHandleWrapper(handler http.HandlerFunc, pri ...string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		userMngr, err := Provider().OpenUserMngr()
		if err != nil {
			InternalErrorResponse(rw, &JSONErr{Message: err.Error()})
		}
		defer userMngr.Close()

		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		user, err := userMngr.GetUser(token)
		if err != nil {
			if err == ErrNotLogged {
				ForbiddenResponse(rw, &JSONErr{
					Code:        ErrCodeNotLogged,
					Message:     err.Error(),
					Description: "User need to be logged in to perform this action.",
				})
				return
			}
			InternalErrorResponse(rw, &JSONErr{Message: err.Error()})
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
			ForbiddenResponse(rw, &JSONErr{
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
