package rest

import (
	"errors"
	"github.com/gorilla/mux"
	"github.com/kidstuff/WebAuth/auth"
	"net/http"
)

func getUserByIdURL(rw http.ResponseWriter, req *http.Request) (*auth.User, auth.UserManager, error) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	vars := mux.Vars(req)
	idStr := vars["id"]
	if len(idStr) == 0 {
		auth.BadRequestResponse(rw, &auth.JSONErr{
			Code:        ErrCodeInvalidId,
			Message:     "Missing 'id' from request",
			Description: "The request URI must be /active/{id}?code=xxxx",
		})
		return nil, nil, errors.New("rest: Missing 'id' from request")
	}

	userMngr, err := auth.Provider().OpenUserMngr(req)
	if err != nil {
		auth.InternalErrorResponse(rw, &auth.JSONErr{Message: err.Error()})
		return nil, nil, err
	}
	defer userMngr.Close()

	u, err := userMngr.FindUser(idStr)
	if err != nil {
		auth.ErrorResponse(rw, http.StatusPreconditionFailed, &auth.JSONErr{
			Code:    ErrCodeNotExistId,
			Message: "Account not exists",
		})
		return nil, userMngr, err
	}

	return u, userMngr, nil
}
