package rest

import (
	"encoding/json"
	"github.com/kidstuff/WebAuth/auth"
	"github.com/kidstuff/WebAuth/rest/config"
	"github.com/kidstuff/WebAuth/rest/util"
	"net/http"
)

const (
	ErrCodeInvalidCredential float32 = 1.2
	ErrCodePwdMismatch       float32 = 1.3
	ErrCodeInvlaidPwd        float32 = 1.4
	ErrCodeDupEmail          float32 = 1.5
	ErrCodeInvalidEmail      float32 = 1.6
)

func SignUp(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	userMngr, err := auth.Provider().OpenUserMngr(req)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{Message: err.Error()})
		return
	}
	defer userMngr.Close()

	credential := struct {
		Email     string
		Pwd       string
		PwdRepeat string
	}{}

	err = json.NewDecoder(req.Body).Decode(&credential)
	if err != nil {
		auth.BadRequestResponse(rw, &auth.JSONErr{
			Code:        ErrCodeInvalidCredential,
			Message:     err.Error(),
			Description: "Credential must be an valid json object contain Email, Pwd and PwdRepeat.",
		})
		return
	}

	if credential.Pwd != credential.PwdRepeat {
		auth.BadRequestResponse(rw, &auth.JSONErr{
			Code:    ErrCodePwdMismatch,
			Message: "Pwd and PwdRepeat doesn't match",
		})
		return
	}

	u, err := userMngr.AddUser(credential.Email, credential.PwdRepeat, false)
	if err != nil {
		switch err {
		case auth.ErrInvalidEmail:
			auth.ErrorResponse(rw, http.StatusPreconditionFailed, &auth.JSONErr{
				Code:    ErrCodeInvalidEmail,
				Message: err.Error(),
			})
		case auth.ErrInvalidPassword:
			auth.ErrorResponse(rw, http.StatusPreconditionFailed, &auth.JSONErr{
				Code:    ErrCodeInvlaidPwd,
				Message: err.Error(),
			})
		case auth.ErrDuplicateEmail:
			auth.ErrorResponse(rw, http.StatusPreconditionFailed, &auth.JSONErr{
				Code:    ErrCodeDupEmail,
				Message: err.Error(),
			})
		default:
			auth.InternalErrorResponse(rw, &auth.JSONErr{Message: err.Error()})
		}
		return
	}

	conf, err := config.Provider().OpenConfigurator(req)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{Message: err.Error()})
		return
	}
	defer conf.Close()

	err = util.SendSimpleMail(conf, u.Email, "Email confirm", u.ConfirmCodes["activate"])
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{Message: err.Error()})
		return
	}

	rw.Write([]byte(`{"message":"email sent to ` + u.Email + `"}`))
}

func ActiveAccount(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	userMngr, err := auth.Provider().OpenUserMngr(req)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{Message: err.Error()})
		return
	}
	defer userMngr.Close()

	//userMngr.ValidConfirmCode(id, key, code, false, true)
}
