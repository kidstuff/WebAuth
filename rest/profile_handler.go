package rest

import (
	"encoding/json"
	"github.com/kidstuff/WebAuth/auth"
	"github.com/kidstuff/WebAuth/rest/util"
	"github.com/kidstuff/WebUtil/config"
	"github.com/kidstuff/WebUtil/dblog"
	"github.com/kidstuff/WebUtil/response"
	"log"
	"net/http"
	"os"
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

	u, userMngr, err := getUserByIdAndWriteIfError(rw, req)
	if err != nil {
		return
	}
	defer userMngr.Close()

	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	currentUser, err := userMngr.GetUser(token)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{
			Message:     err.Error(),
			Description: "Error when loading current user.",
		})
		return
	}

	if currentUser.Id != u.Id {
		if !userMngr.Can(currentUser, "manage_user") {
			response.ForbiddenResponse(rw, &response.JSONErr{
				Code:        response.ErrNoPermission,
				Message:     "Current user doesn't have valid permission.",
				Description: "Current user need 'manage_user' permission to perform this action.",
			})
			return
		}
	}

	var inf auth.UserInfo
	err = json.NewDecoder(req.Body).Decode(&inf)
	if err != nil {
		response.BadRequestResponse(rw, &response.JSONErr{
			Code:        ErrCodeInvalidInput,
			Message:     err.Error(),
			Description: "The request body must be a valid response.UserInfo JSON object",
		})
		return
	}
	defer req.Body.Close()

	u.Info = inf
	err = userMngr.UpdateUserDetail(u)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{
			Message:     err.Error(),
			Description: "Error when saving user object to database.",
		})
		return
	}

}

/*
UserInfoDetail handle the request for getting user account info.

Example Request Body:
  GET /profile/some-kind-of-ID/info
Example Success Response
  {
    "FirstName": "Cao Nguyên"
    ...//other feilds of auth,UserInfo struct
  }
*/
func UserInfoDetail(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	u, userMngr, err := getUserByIdAndWriteIfError(rw, req)
	if err != nil {
		return
	}
	defer userMngr.Close()

	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	currentUser, err := userMngr.GetUser(token)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{
			Message:     err.Error(),
			Description: "Error when loading current user.",
		})
		return
	}

	if currentUser.Id != u.Id {
		if !userMngr.Can(currentUser, "manage_user") {
			response.ForbiddenResponse(rw, &response.JSONErr{
				Code:        response.ErrNoPermission,
				Message:     "Current user doesn't have valid permission.",
				Description: "Current user need 'manage_user' permission to perform this action.",
			})
			return
		}
	}

	json.NewEncoder(rw).Encode(u.Info)
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

	u, userMngr, err := getUserByIdAndWriteIfError(rw, req)
	if err != nil {
		return
	}
	defer userMngr.Close()

	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	currentUser, err := userMngr.GetUser(token)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{
			Message:     err.Error(),
			Description: "Error when loading current user.",
		})
		return
	}

	var can_manage_user bool

	if currentUser.Id != u.Id {
		if can_manage_user = userMngr.Can(currentUser, "manage_user"); !can_manage_user {
			response.ForbiddenResponse(rw, &response.JSONErr{
				Code:        response.ErrNoPermission,
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
		response.BadRequestResponse(rw, &response.JSONErr{
			Code:        ErrCodeInvalidInput,
			Message:     err.Error(),
			Description: "The request body mus contain an JSON object with valid Pwd, NewPwd and NewPwdRepeat field.",
		})
		return
	}

	if pwdChange.NewPwd != pwdChange.NewPwdRepeat {
		response.BadRequestResponse(rw, &response.JSONErr{
			Code:    ErrCodePwdMismatch,
			Message: "NewPwd doesn't match.",
		})
		return
	}

	if !can_manage_user {
		if u.ComparePassword(pwdChange.Pwd) != nil {
			response.ForbiddenResponse(rw, &response.JSONErr{
				Code:        ErrCodeInvlaidPwd,
				Message:     "Invalid passsword",
				Description: "Your provied password are invlaid.",
			})
			return
		}
	}

	err = u.ChangePassword(pwdChange.NewPwd)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{
			Message:     err.Error(),
			Description: "Error when update user password.",
		})
		return
	}

	if !can_manage_user {
		rw.WriteHeader(http.StatusAccepted)
		go func() {
			var logger *log.Logger
			logdbw, err := dblog.Provider().OpenLogger(req)
			if err != nil {
				// use std log... :(
				// mostly never be in appengine env
				logger = log.New(os.Stdout, "", log.LstdFlags)
				logger.Println("rest: cannot OpenLogger")
			} else {
				logger = log.New(logdbw, "", 4)
			}

			conf, err := config.Provider().OpenConfigurator(req)
			if err != nil {
				logger.Println("rest: OpenConfigurator", err)
				return
			}
			defer conf.Close()

			mess, err := conf.Get("pwd_change_message")
			if err != nil {
				logger.Println("rest: Configurator can't load 'pwd_change_message'", err)
			}

			err = util.SendSimpleMail(conf, u.Email, "Password changed", mess)
			if err != nil {
				logger.Println("rest: SendSimpleMail", err)
			}
		}()
	}

	rw.Write([]byte(`{"Message":"Password for user ` + u.Email + ` has been updated."}`))
}

func UserList(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	userMngr, err := auth.Provider().OpenUserMngr(req)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
		return
	}
	defer userMngr.Close()

	uLst, err := userMngr.FindAllUser("", -1)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{
			Message:     err.Error(),
			Description: "Error when FindAllUser.",
		})
		return
	}

	for _, v := range uLst {
		v.Pwd = auth.Password{}
		v.OldPwd = []auth.Password{}
		v.Info = auth.UserInfo{}
		v.ConfirmCodes = make(map[string]string)
	}

	json.NewEncoder(rw).Encode(uLst)
}
