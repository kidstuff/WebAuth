package gaeauth

import (
	"appengine"
	"appengine/datastore"
	"github.com/kidstuff/WebAuth/auth"
	"time"
)

// user use to add additional method to origin User struct from auth package
type user struct {
	auth.User
	confirmCodesKey []string
	confirmCodesVal []string
}

func (u *user) Load(c <-chan datastore.Property) error {
	if err := datastore.LoadStruct(u, c); err != nil {
		return err
	}

	u.ConfirmCodes = make(map[string]string)
	for i := 0; i < len(u.confirmCodesKey); i++ {
		u.ConfirmCodes[u.confirmCodesKey[i]] = u.confirmCodesVal[i]
	}

	// should I do this?
	u.confirmCodesKey = nil
	u.confirmCodesVal = nil

	return nil
}

func (u *user) Save(c chan<- datastore.Property) error {
	n := len(u.ConfirmCodes)
	u.confirmCodesKey = make([]string, 0, n)
	u.confirmCodesVal = make([]string, 0, n)
	for key, val := range u.ConfirmCodes {
		u.confirmCodesKey = append(u.confirmCodesKey, key)
		u.confirmCodesVal = append(u.confirmCodesVal, val)
	}

	return datastore.SaveStruct(u, c)
}

type GAEUserManager struct {
	ctx      appengine.Context
	Formater auth.FormatChecker
}

func (m *GAEUserManager) GroupManager() auth.GroupManager {
	panic("not implemeted")

}

func (m *GAEUserManager) newUser(email, pwd string, app bool) (*auth.User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, auth.ErrInvalidEmail
	}

	if !m.Formater.PasswordValidate(pwd) {
		return nil, auth.ErrInvalidPassword
	}

	u := &auth.User{}
	u.Email = email
	u.LastActivity = time.Now()
	u.Info.JoinDay = u.LastActivity

	p, err := auth.HashPwd(pwd)
	if err != nil {
		return nil, err
	}

	u.Pwd = p

	u.Approved = app
	return u, nil
}

func (m *GAEUserManager) insertUser(u *auth.User) error {
	n, err := datastore.NewQuery("User").Filter("Email =", u.Email).Count(m.ctx)
	if n > 0 {
		return auth.ErrDuplicateEmail
	}

	u.Id, err = datastore.Put(m.ctx, datastore.NewIncompleteKey(m.ctx, "User", nil), u)
	if err != nil {
		return err
	}

	return nil
}

func (m *GAEUserManager) AddUser(email, pwd string, app bool) (*auth.User, error) {
	user, err := m.newUser(email, pwd, app)
	if err != nil {
		return nil, err
	}

	err = m.insertUser(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (m *GAEUserManager) AddUserDetail(user *auth.User) (*auth.User, error) {
	err := m.insertUser(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (m *GAEUserManager) UpdateUserDetail(user *auth.User) error {
	panic("not implemeted")

}

func (m *GAEUserManager) DeleteUser(id interface{}) error {
	panic("not implemeted")

}

func (m *GAEUserManager) FindUser(id interface{}) (*auth.User, error) {
	panic("not implemeted")

}

func (m *GAEUserManager) FindUserByEmail(email string) (*auth.User, error) {
	panic("not implemeted")

}

func (m *GAEUserManager) FindAllUser(offsetId interface{}, limit int) ([]*auth.User, error) {
	panic("not implemeted")

}

func (m *GAEUserManager) FindAllUserOnline(offsetId interface{}, limit int) ([]*auth.User, error) {
	panic("not implemeted")

}

func (m *GAEUserManager) ValidateUser(email, pwd string) (*auth.User, error) {
	panic("not implemeted")

}

func (m *GAEUserManager) GetUser(token string) (*auth.User, error) {
	panic("not implemeted")

}

func (m *GAEUserManager) Login(id interface{}, stay time.Duration) (string, error) {
	panic("not implemeted")

}

func (m *GAEUserManager) Logout(token string) error {
	panic("not implemeted")

}

func (m *GAEUserManager) Can(user *auth.User, do string) bool {
	panic("not implemeted")
}

func (m *GAEUserManager) Close() error {
	panic("not implemeted")
}

var _ auth.UserManager = &GAEUserManager{}
