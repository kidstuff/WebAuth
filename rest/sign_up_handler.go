package rest

import (
	"encoding/json"
	"github.com/kidstuff/WebAuth/auth"
	"net/http"
)

func SignUp(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	userMngr, err := auth.Provider().OpenUserMngr()
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
		auth.BadRequestResponse(rw, &auth.JSONErr{Message: err.Error()})
		return
	}

	var email, pwd string
	var app bool
	userMngr.AddUser(email, pwd, app)
}
