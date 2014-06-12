package auth

import (
	"github.com/gorilla/mux"
	"github.com/kidstuff/WebUtil/response"
	"net/http"
	"strings"
)

func OAuthHandleWrapper(handler http.HandlerFunc, groups []string, pri []string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		userMngr, err := Provider().OpenUserMngr(req)
		if err != nil {
			response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
		}
		defer userMngr.Close()

		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		user, err := userMngr.GetUser(token)
		if err != nil {
			if err == ErrNotLogged {
				response.ForbiddenResponse(rw, &response.JSONErr{
					Code:        response.ErrCodeNotLogged,
					Message:     err.Error(),
					Description: "User need to be logged in to perform this action.",
				})
				return
			}
			response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
			return
		}

		if len(groups) > 0 {
			for _, bg := range user.BriefGroups {
				for _, g2 := range groups {
					if bg.Name == g2 {
						handler(rw, req)
						return
					}
				}
			}
		}

		var (
			cannot   bool
			cannotDo string
		)
		for _, do := range pri {
			if !userMngr.Can(user, do) {
				cannotDo += do + ","
			}
		}

		if cannot {
			response.ForbiddenResponse(rw, &response.JSONErr{
				Code:        response.ErrNoPermission,
				Message:     "User doesn't have valid permission.",
				Description: "User doesn't have " + cannotDo + " permission.",
			})
			return
		}

		// run user defined handler
		handler(rw, req)
	}
}

func OAuthOwnerPrivilegeWrapper(handler http.HandlerFunc, userIdField string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		userMngr, err := Provider().OpenUserMngr(req)
		if err != nil {
			response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
		}
		defer userMngr.Close()

		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		user, err := userMngr.GetUser(token)
		if err != nil {
			if err == ErrNotLogged {
				response.ForbiddenResponse(rw, &response.JSONErr{
					Code:        response.ErrCodeNotLogged,
					Message:     err.Error(),
					Description: "User need to be logged in to perform this action.",
				})
				return
			}
			response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
			return
		}

		vars := mux.Vars(req)
		idStr := vars[userIdField]
		if len(idStr) == 0 {
			response.BadRequestResponse(rw, &response.JSONErr{
				Message:     "Missing " + userIdField + " from request URL",
				Description: "OAuthOwnerPrivilegeWrapper require " + userIdField + " defiend by 'userIdField' to be exist in handle pattern.",
			})
			return
		}

		u, err := userMngr.FindUser(idStr)
		if err != nil {
			response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
			return
		}

		if u.Id != user.Id {
			response.ForbiddenResponse(rw, &response.JSONErr{
				Code:        response.ErrNoPermission,
				Message:     "Current user must be the owner of profile.",
				Description: "Current user must be the owner of the profile defined by " + userIdField + " field.",
			})
			return
		}

		handler(rw, req)
	}
}
