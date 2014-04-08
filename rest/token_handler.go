package rest

import (
	"encoding/json"
	"github.com/kidstuff/WebAuth/auth"
	"net/http"
	"time"
)

type LoginInfo struct {
	User        *auth.User
	ExpiredOn   time.Time
	AccessToken string
}

func GetToken(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	userMngr, err := auth.Provider().OpenUserMngr()
	if err != nil {
		print(err.Error())
		auth.InternalServerErrorHanlder(rw, req)
		return
	}

	grantType := req.FormValue("grant_type")
	email := req.FormValue("email")
	password := req.FormValue("password")

	// TODO: more detail error message
	if len(grantType) == 0 || len(email) == 0 || len(password) == 0 {
		auth.BadRequestHanlder(rw, req)
		return
	}

	if grantType != "password" {
		http.Error(rw, `{"error":"Only passowrd grant_type supported"}`,
			http.StatusNotImplemented)
		return
	}

	user, err := userMngr.ValidateUser(email, password)
	if err != nil {
		http.Error(rw, `{"error":"Invlaid emaill or password"}`,
			http.StatusUnauthorized)
		return
	}

	token, err := userMngr.Login(user.Id, OnlineThreshold)
	if err != nil {
		auth.InternalServerErrorHanlder(rw, req)
		return
	}

	// hide sensitive data
	user.Pwd = auth.Password{}
	user.OldPwd = user.Pwd
	user.ConfirmCodes = map[string]string{}

	inf := LoginInfo{user, time.Now().Add(OnlineThreshold), token}
	json.NewEncoder(rw).Encode(&inf)
}
