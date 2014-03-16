package rest

import (
	"github.com/kidstuff/WebAuth/auth"
	"net/http"
)

func GetToken(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	userMngr, err := auth.Provider().OpenUserMngr()
	if err != nil {
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
		http.Error(rw, `{error:"Only passowrd grant_type supported"}`,
			http.StatusNotImplemented)
		return
	}

	user, err := userMngr.ValidateUser(email, password)
	if err != nil {
		http.Error(rw, `{error:"Invlaid emaill or password"}`,
			http.StatusUnauthorized)
		return
	}

	token, err := userMngr.Login(user.Id, 300)
	if err != nil {
		auth.InternalServerErrorHanlder(rw, req)
		return
	}

	rw.Write([]byte(`{access_token:"` + token + `"}`))
}
