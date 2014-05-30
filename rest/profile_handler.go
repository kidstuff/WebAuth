package rest

import (
	"encoding/json"
	"github.com/kidstuff/WebAuth/auth"
	"github.com/kidstuff/WebAuth/rest/config"
	"github.com/kidstuff/WebAuth/rest/util"
	"log"
	"net/http"
	"strings"
)

/*
UserInfoUpdate handle the reuqest for update user infomation. Its require 'manage_user'
to change other's infomation.

Example Request Body:
  PUT /profile/some-kind-of-ID/info
  {
    "FirstName": "Cao Nguyên"
    ...//other feilds of auth,UserInfo struct
  }
*/
func UserInfoUpdate(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	u, userMngr, err := getUserByIdURL(rw, req)
	if err != nil {
		return
	}

	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	currentUser, err := userMngr.GetUser(token)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{
			Message:     err.Error(),
			Description: "Error when loading current user.",
		})
		return
	}

	if currentUser.Id != u.Id {
		if !userMngr.Can(currentUser, "manage_user") {
			auth.ForbiddenResponse(rw, &auth.JSONErr{
				Code:        auth.ErrNoPermission,
				Message:     "Current user doesn't have valid permission.",
				Description: "Current user need 'manage_user' permission to perform this action.",
			})
			return
		}
	}

	var inf auth.UserInfo
	err = json.NewDecoder(req.Body).Decode(&inf)
	if err != nil {
		auth.BadRequestResponse(rw, &auth.JSONErr{
			Code:        ErrCodeInvalidInput,
			Message:     err.Error(),
			Description: "The request body must be a valid auth.UserInfo JSON object",
		})
		return
	}
	defer req.Body.Close()

	u.Info = inf
	err = userMngr.UpdateUserDetail(u)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{
			Message:     err.Error(),
			Description: "Error when saving user object to database.",
		})
		return
	}

}

/*
PasswordUpdate handle the request for changin user password. its require 'manage_user' permission to
change other's password.

Example Request Body:
  POST /profile/some-kind-of-ID/change-password
  {
    "Pwd": "xxxxxxxxx",
    "NewPwd": "yyyyyyyyy",
    "NewPwdRepeat": "yyyyyyyyy"
  }
Example Success Response:
{
  "Message":"Password for user  has been updated."
}
*/
func PasswordUpdate(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	u, userMngr, err := getUserByIdURL(rw, req)
	if err != nil {
		return
	}

	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	currentUser, err := userMngr.GetUser(token)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{
			Message:     err.Error(),
			Description: "Error when loading current user.",
		})
		return
	}

	var can_manage_user bool

	if currentUser.Id != u.Id {
		if can_manage_user = userMngr.Can(currentUser, "manage_user"); !can_manage_user {
			auth.ForbiddenResponse(rw, &auth.JSONErr{
				Code:        auth.ErrNoPermission,
				Message:     "Current user doesn't have valid permission.",
				Description: "Current user need 'manage_user' permission to perform this action.",
			})
			return
		}
	}

	pwdChange := struct {
		Pwd          string
		NewPwd       string
		NewPwdRepeat string
	}{}

	err = json.NewDecoder(req.Body).Decode(&pwdChange)
	if err != nil {
		auth.BadRequestResponse(rw, &auth.JSONErr{
			Code:        ErrCodeInvalidInput,
			Message:     err.Error(),
			Description: "The request body mus contain an JSON object with valid Pwd, NewPwd and NewPwdRepeat field.",
		})
		return
	}

	if pwdChange.NewPwd != pwdChange.NewPwdRepeat {
		auth.BadRequestResponse(rw, &auth.JSONErr{
			Code:    ErrCodePwdMismatch,
			Message: "NewPwd doesn't match.",
		})
		return
	}

	if !can_manage_user {
		if u.ComparePassword(pwdChange.Pwd) != nil {
			auth.ForbiddenResponse(rw, &auth.JSONErr{
				Code:        ErrCodeInvlaidPwd,
				Message:     "Invalid passsword",
				Description: "Your provied password are invlaid.",
			})
			return
		}
	}

	err = u.ChangePassword(pwdChange.NewPwd)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{
			Message:     err.Error(),
			Description: "Error when update user password.",
		})
		return
	}

	if !can_manage_user {
		rw.WriteHeader(http.StatusAccepted)
		go func() {
			conf, err := config.Provider().OpenConfigurator(req)
			if err != nil {
				return
			}

			mess, err := conf.Get("pwd_change_message")
			if err != nil {
				log.Println("rest: Configurator can't load 'pwd_change_message'", err)
			}

			err = util.SendSimpleMail(conf, u.Email, "Password changed", mess)
			if err != nil {
				log.Println("rest: SendSimpleMail", err)
			}
			conf.Close()
		}()
	}

	rw.Write([]byte(`{"Message":"Password for user ` + u.Email + ` has been updated."}`))
}
