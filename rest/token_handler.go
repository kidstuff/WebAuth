package rest

import (
	"encoding/json"
	"github.com/kidstuff/WebAuth/auth"
	"net/http"
	"time"
)

const (
	ErrCodeInvalidInput     float32 = 1.0
	ErrCodeInvalidGrantType float32 = 1.1
)

type LoginInfo struct {
	User        *auth.User
	ExpiredOn   time.Time
	AccessToken string
}

/*
GetToken handle both POST and GET method to obtain login token.
Note that only "password" support for "grant_type" right now.

Example Request:
  GET /tokens?grant_type=password&email=nguyen@open-vn.org&password=xxxxxxxxx
Example Success Response:
  {
    "User": {...}, // auth.User object with empty Pwd, OldPwd, ConfirmCodes
    "ExpiredOn": "2009-11-10T23:00:00Z",
    "AccessToken": "afE.....MNWt-HfVYcFOs7w_ryOzvsYA==" // a secure random base64 encoded string
  }
*/
func GetToken(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	userMngr, err := auth.Provider().OpenUserMngr(req)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{Message: err.Error()})
		return
	}
	defer userMngr.Close()

	grantType := req.FormValue("grant_type")
	email := req.FormValue("email")
	password := req.FormValue("password")

	// TODO: more detail error message
	if len(grantType) == 0 || len(email) == 0 || len(password) == 0 {
		auth.BadRequestResponse(rw, &auth.JSONErr{
			Code:        ErrCodeInvalidInput,
			Message:     "Invalid input",
			Description: "grant_type, email and password need to be set.",
		})
		return
	}

	if grantType != "password" {
		auth.ErrorResponse(rw, http.StatusNotImplemented, &auth.JSONErr{
			Code:        ErrCodeInvalidGrantType,
			Message:     "Invlaid grant_type",
			Description: "Only support grant_type=password",
		})
		return
	}

	user, err := userMngr.ValidateUser(email, password)
	if err != nil {
		auth.UnauthorizedResponse(rw, &auth.JSONErr{
			Code:        auth.ErrCodeNotLogged,
			Message:     err.Error(),
			Description: "Invlaid emaill or password.",
		})
		return
	}

	token, err := userMngr.Login(user.Id, OnlineThreshold)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{Message: err.Error()})
		return
	}

	// hide sensitive data
	user.Pwd = auth.Password{}
	user.OldPwd = []auth.Password{}
	user.ConfirmCodes = map[string]string{}

	inf := LoginInfo{user, time.Now().Add(OnlineThreshold), token}
	json.NewEncoder(rw).Encode(&inf)
}
