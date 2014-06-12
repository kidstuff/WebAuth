package rest

import (
	"encoding/json"
	"github.com/kidstuff/WebAuth/auth"
	"github.com/kidstuff/WebAuth/rest/util"
	"github.com/kidstuff/WebUtil/config"
	"github.com/kidstuff/WebUtil/response"
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
		response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
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
		response.BadRequestResponse(rw, &response.JSONErr{
			Code:        ErrCodeInvalidCredential,
			Message:     err.Error(),
			Description: "Credential must be an valid json object contain Email, Pwd and PwdRepeat.",
		})
		return
	}

	if credential.Pwd != credential.PwdRepeat {
		response.BadRequestResponse(rw, &response.JSONErr{
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
			response.ErrorResponse(rw, http.StatusPreconditionFailed, &response.JSONErr{
				Code:    ErrCodeInvalidEmail,
				Message: err.Error(),
			})
		case auth.ErrInvalidPassword:
			response.ErrorResponse(rw, http.StatusPreconditionFailed, &response.JSONErr{
				Code:    ErrCodeInvlaidPwd,
				Message: err.Error(),
			})
		case auth.ErrDuplicateEmail:
			response.ErrorResponse(rw, http.StatusPreconditionFailed, &response.JSONErr{
				Code:    ErrCodeDupEmail,
				Message: err.Error(),
			})
		default:
			response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
		}
		return
	}

	conf, err := config.Provider().OpenConfigurator(req)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
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

	code := req.FormValue("code")
	if len(code) == 0 {
		response.BadRequestResponse(rw, &response.JSONErr{
			Code:        1.8,
			Message:     "Missing 'code' from request parameter",
			Description: "The request URI must be /active/{id}?code=xxxx",
		})
		return
	}

	u, userMngr, err := getUserByIdAndWriteIfError(rw, req)
	if err != nil {
		return
	}
	defer userMngr.Close()

	if ok := u.ValidConfirmCode("activate", code, false, true); !ok {
		response.ErrorResponse(rw, http.StatusPreconditionFailed, &response.JSONErr{
			Code:    1.8,
			Message: "Invlaid activate code",
		})
		return
	}

	u.Approved = true
	err = userMngr.UpdateUserDetail(u)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{
			Message:     err.Error(),
			Description: "Error when updating user infomation to database.",
		})
		return
	}

	rw.Write([]byte(`{"Message":"Account activated"}`))
}
