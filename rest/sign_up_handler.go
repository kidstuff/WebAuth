package rest

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/kidstuff/WebAuth/auth"
	"github.com/kidstuff/WebAuth/rest/config"
	"github.com/kidstuff/WebAuth/rest/util"
	"log"
	"net/http"
)

const (
	ErrCodeInvalidCredential float32 = 1.2
	ErrCodePwdMismatch       float32 = 1.3
	ErrCodeInvlaidPwd        float32 = 1.4
	ErrCodeDupEmail          float32 = 1.5
	ErrCodeInvalidEmail      float32 = 1.6
	ErrCodeInvalidId         float32 = 1.7
	ErrCodeNotExistId        float32 = 1.9
)

/*
SignUp handle the request for account sign-up. The handler will
check the email and password format. If success it will send an
email and immediately return a 202 status code.

Example Request Body:
  POST /signup
  {
    "Email": "nguyen@open-vn.org",
    "Pwd": "xxxxxxxxx",
    "PwdRepeat": "xxxxxxxxx"
  }
Example Success Response:
  {
    "Message":"email sent to nguyen@open-vn.org"
  }
*/
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

	var app bool

	u, err := userMngr.AddUser(credential.Email, credential.PwdRepeat, app)
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

	if !app {
		// TODO(!)
		// time out control for mail send
		go func() {
			err = util.SendSimpleMail(conf, u.Email, "Email confirm", u.ConfirmCodes["activate"])
			if err != nil {
				log.Println("rest: SendSimpleMail", err)
			}
			conf.Close()
		}()
	}

	rw.WriteHeader(http.StatusAccepted)
	rw.Write([]byte(`{"Message":"email sent to ` + u.Email + `"}`))
}

/*
ActiveAccount handle active request by using confirm code.

Example Request:
  GET /active/some-kind-of-ID?code=secure-random-base64-string
Example Success Response:
  {
    "Message":"Account activated"
  }
*/
func ActiveAccount(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	vars := mux.Vars(req)
	idStr := vars["id"]
	if len(idStr) == 0 {
		auth.BadRequestResponse(rw, &auth.JSONErr{
			Code:        ErrCodeInvalidId,
			Message:     "Missing 'id' from request",
			Description: "The request URI must be /active/{id}?code=xxxx",
		})
		return
	}

	code := req.FormValue("code")
	if len(code) == 0 {
		auth.BadRequestResponse(rw, &auth.JSONErr{
			Code:        1.8,
			Message:     "Missing 'code' from request parameter",
			Description: "The request URI must be /active/{id}?code=xxxx",
		})
		return
	}

	userMngr, err := auth.Provider().OpenUserMngr(req)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{Message: err.Error()})
		return
	}
	defer userMngr.Close()

	u, err := userMngr.FindUser(idStr)
	if err != nil {
		auth.ErrorResponse(rw, http.StatusPreconditionFailed, &auth.JSONErr{
			Code:    ErrCodeNotExistId,
			Message: "Account not exists",
		})
		return
	}

	if ok := u.ValidConfirmCode("activate", code, false, true); !ok {
		auth.ErrorResponse(rw, http.StatusPreconditionFailed, &auth.JSONErr{
			Code:    1.8,
			Message: "Invlaid activate code",
		})
		return
	}

	u.Approved = true
	err = userMngr.UpdateUserDetail(u)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{
			Message:     err.Error(),
			Description: "Error when updating user infomation to database.",
		})
		return
	}

	rw.Write([]byte(`{"Message":"Account activated"}`))
}
