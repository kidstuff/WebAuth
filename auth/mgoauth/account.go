package mgoauth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/base64"
	"github.com/gorilla/securecookie"
	"github.com/kidstuff/WebAuth/auth"
	"github.com/kidstuff/mongostore"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"net/http"
	"time"
)

type Account struct {
	Id           bson.ObjectId `bson:"_id"`
	auth.Account `bson:",inline"`
}

// GetId returns an bson.ObjectId hex string
func (a *Account) GetId() interface{} {
	return a.Id.Hex()
}

// SetId must recive a valid bson.ObjectId hex string, otherwise an
// ErrInvalidIdHex returned.
func (a *Account) SetId(id interface{}) error {
	sid, ok := id.(string)
	if !ok {
		return auth.ErrInvalidId
	}

	if !bson.IsObjectIdHex(sid) {
		return auth.ErrInvalidId
	}

	a.Id = bson.ObjectIdHex(sid)
	return nil
}

type MgoUserManager struct {
	UserColl    *mgo.Collection
	LoginColl   *mgo.Collection
	Formater    FormatChecker
	SessionMngr mongostore.MongoStore
	dbsess      *mgo.Session
	groupMngr   auth.GroupManager
	req         *http.Request
	rw          http.ResponseWriter
	sessionName string
	cookieName  string
}

// SetGroupManager sets GroupManager use for the Can method.
func (m *MgoUserManager) SetGroupManager(mngr auth.GroupManager) {
	m.groupMngr = mngr
}

func hashPwd(pwd string) (auth.Password, error) {
	p := auth.Password{}
	p.InitAt = time.Now()
	p.Salt = securecookie.GenerateRandomKey(32)

	pwdBytes := []byte(pwd)
	tmp := make([]byte, len(pwdBytes)+len(p.Salt))
	copy(tmp, pwdBytes)
	tmp = append(tmp, p.Salt...)
	b, err := bcrypt.GenerateFromPassword(tmp, bcrypt.DefaultCost)
	p.Hashed = b

	return p, err
}

func (m *MgoUserManager) newUser(email, pwd string, app bool) (*Account, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, auth.ErrInvalidEmail
	}

	if !m.Formater.PasswordValidate(pwd) {
		return nil, auth.ErrInvalidPassword
	}

	u := &Account{}
	u.Id = bson.NewObjectId()
	u.Email = email

	p, err := hashPwd(pwd)
	if err != nil {
		return nil, err
	}

	u.Pwd = p

	u.Approved = app
	return u, nil
}

func (m *MgoUserManager) insertUser(u auth.User) error {
	err := m.UserColl.Insert(u)
	if err != nil {
		if mgo.IsDup(err) {
			return auth.ErrDuplicateEmail
		}
		return err
	}

	return nil
}

// AddUser adds an user to database with email and password;
// If app is false, the user is waiting to be approved.
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) AddUser(email, pwd string, app bool) (auth.User,
	error) {
	u, err := m.newUser(email, pwd, app)
	if err != nil {
		return nil, err
	}

	err = m.insertUser(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

// AddUserInfo adds an user to database;
// If app is false, the user is waiting to be approved.
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) AddUserDetail(email, pwd string, app bool,
	info auth.UserInfo, pri map[string]bool) (auth.User, error) {
	u, err := m.newUser(email, pwd, app)
	if err != nil {
		return nil, err
	}

	u.Privilege = pri
	u.Info = info

	err = m.insertUser(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

// UpdateInfo changes information of user specify by id.
func (m *MgoUserManager) UpdateInfo(id interface{}, info auth.UserInfo) error {
	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return auth.ErrInvalidId
	}

	return m.UserColl.UpdateId(bson.ObjectIdHex(sid), bson.M{
		"$set": bson.M{"info": info},
	})
}

// UpdatePrivilege changes privilege of user specify by id.
func (m *MgoUserManager) UpdatePrivilege(id interface{}, pri map[string]bool) error {
	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return auth.ErrInvalidId
	}

	return m.UserColl.UpdateId(bson.ObjectIdHex(sid), bson.M{
		"$set": bson.M{"privilege": pri},
	})
}

// ChangePassword changes passowrd of user specify by id.
func (m *MgoUserManager) ChangePassword(id interface{}, pwd string) error {
	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return auth.ErrInvalidId
	}

	oid := bson.ObjectIdHex(sid)
	acc := Account{}
	err := m.UserColl.FindId(oid).One(&acc)
	if err != nil {
		return err
	}

	p, err := hashPwd(pwd)
	if err != nil {
		return err
	}

	return m.UserColl.UpdateId(oid, bson.M{"$set": bson.M{
		"oldpwd": acc.GetOldPassword(),
		"pwd":    p,
	}})
}

// DeleteUserByEmail deletes an user from database base on the given id;
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) DeleteUser(id interface{}) error {
	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return auth.ErrInvalidId
	}

	return m.UserColl.RemoveId(m.UserColl.RemoveId(bson.ObjectIdHex(sid)))
}

// FindUser finds the user with the given id;
// Its returns an ErrNotFound if the user's id was not found.
func (m *MgoUserManager) FindUser(id interface{}) (auth.User, error) {
	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return nil, auth.ErrInvalidId
	}

	acc := &Account{}
	err := m.UserColl.FindId(bson.ObjectIdHex(sid)).One(acc)
	if err != nil {
		return nil, err
	}

	return acc, nil
}

// FindUserByEmail like FindUser but receive an email
func (m *MgoUserManager) FindUserByEmail(email string) (auth.User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, auth.ErrInvalidEmail
	}

	acc := &Account{}
	err := m.UserColl.Find(bson.M{"email": email}).One(acc)
	if err != nil {
		return nil, err
	}

	return acc, nil
}

func (m *MgoUserManager) findAllUser(offsetKey interface{}, limit int, filter bson.M) ([]auth.User, error) {
	if limit < 0 {
		return nil, nil
	}

	if offsetKey != nil {
		sid, ok := offsetKey.(string)
		if !ok {
			return nil, auth.ErrInvalidId
		} else {
			if filter == nil {
				filter = bson.M{}
			}
			filter["_id"] = bson.M{"$gt": bson.ObjectIdHex(sid)}
		}
	}

	var accounts []Account
	if limit > 0 {
		accounts = make([]Account, 0, limit)
	} else {
		accounts = []Account{}
	}

	err := m.UserColl.Find(filter).Limit(limit).All(&accounts)
	if err != nil {
		return nil, err
	}

	n := len(accounts)
	userLst := make([]auth.User, n, n)

	for idx, acc := range accounts {
		userLst[idx] = &acc
	}

	return userLst, nil
}

// FindAllUser finds and return a slice of user.
// offsetId, limit define which sub-sequence of matching users to return.
// Limit take an number of user per page; offsetId take the Id of the last
// user of the previous page.
func (m *MgoUserManager) FindAllUser(offsetId interface{}, limit int) (
	[]auth.User, error) {
	return m.findAllUser(offsetId, limit, nil)
}

// FindAllUserOline finds and return a slice of current Loged user.
// See FindAllUser for the usage.
func (m *MgoUserManager) FindAllUserOnline(offsetId interface{}, limit int) (
	[]auth.User, error) {
	return m.findAllUser(offsetId, limit, bson.M{
		"lastactivity": bson.M{"$lt": time.Now().
			Add(-time.Duration(m.SessionMngr.Options.MaxAge) * time.Second)},
	})
}

// CountUserOnline counts the number of user current Loged.
// It counts the user that LastActivity+OnlineThreshold<Now.
func (m *MgoUserManager) CountUserOnline() int {
	n, err := m.UserColl.Find(bson.M{"lastactivity": bson.M{
		"$lt": time.Now().
			Add(-time.Duration(m.SessionMngr.Options.MaxAge) * time.Second),
	}}).Count()
	if err == nil {
		return n
	}

	return 0
}

// ValidateUser validate user email and password.
// It returns the user infomations if the email and password is correct.
func (m *MgoUserManager) ValidateUser() (auth.User, error) {
	acc := &Account{}
	err := m.UserColl.Find(bson.M{"email": m.req.FormValue("email")}).One(acc)
	if err != nil {
		return nil, err
	}

	pwdBytes := []byte(m.req.FormValue("password"))
	tmp := make([]byte, len(pwdBytes)+len(acc.Pwd.Salt))
	copy(tmp, pwdBytes)
	tmp = append(tmp, acc.Pwd.Salt...)
	if err := bcrypt.CompareHashAndPassword(acc.Pwd.Hashed, tmp); err != nil {
		return nil, err
	}

	return acc, nil
}

func (m *MgoUserManager) updateLastActivityAccount(id bson.ObjectId) (*Account, error) {
	acc := &Account{}
	err := m.UserColl.FindId(id).One(acc)
	if err != nil {
		return nil, err
	}

	acc.LastActivity = time.Now()
	// ??? should we ignore the error return here?
	err = m.UserColl.UpdateId(id, bson.M{
		"$set": bson.M{"lastactivity": acc.LastActivity},
	})
	if err != nil {
		return nil, err
	}

	return acc, nil
}

// GetUser gets the infomations and update the LastActivity of the current
// Loged user;
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) GetUser() (auth.User, error) {
	cook, cookErr := m.req.Cookie(m.cookieName)
	if cookErr == nil {
		// get user login state save in cookie
		state := LoginState{}
		err := m.LoginColl.FindId(cook.Value).One(&state)
		if err != nil {
			return nil, err
		}

		if state.Exp.Before(time.Now()) {
			m.LoginColl.RemoveId(cook.Value)
			// don't need to call Logout since the cookie with expire soon
			return nil, auth.ErrNotLogged
		}

		return m.updateLastActivityAccount(state.UserId)
	}

	sess, errSess := m.SessionMngr.Get(m.req, m.sessionName)
	if errSess == nil {
		id, ok := sess.Values["login_info"]
		if !ok {
			return nil, auth.ErrNotLogged
		}

		sid, ok := id.(string)
		if !ok || !bson.IsObjectIdHex(sid) {
			return nil, auth.ErrNotLogged
		}

		return m.updateLastActivityAccount(bson.ObjectIdHex(sid))
	}

	return nil, auth.ErrNotLogged
}

// Login logs user in by using a session that store user id.
// Stay take a number of second to keep the user Login state.
func (m *MgoUserManager) Login(id interface{}, stay int) error {
	// try to logout first then login again
	err := m.Logout()
	if err != nil {
		return err
	}

	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return auth.ErrInvalidId
	}

	if stay > 0 {
		// use cookie and remember collection
		state := LoginState{
			UserId: bson.ObjectIdHex(sid), // id of the current user
			Exp:    time.Now().Add(time.Duration(stay) * time.Second),
			Token: base64.URLEncoding.
				EncodeToString(securecookie.GenerateRandomKey(128)),
		}

		http.SetCookie(m.rw, &http.Cookie{
			Name:    m.cookieName,
			Value:   state.Token,
			MaxAge:  stay,
			Expires: state.Exp,
		})

		return m.LoginColl.Insert(&state)
	} else {
		// use session
		sess, err := m.SessionMngr.New(m.req, m.sessionName)
		if err != nil {
			return err
		}

		sess.Values["login_sid"] = sid

		return m.SessionMngr.Save(m.req, m.rw, sess)
	}

	return nil
}

// Logout logs the current user out.
func (m *MgoUserManager) Logout() error {
	cook, err := m.req.Cookie(m.cookieName)
	if err == nil {
		http.SetCookie(m.rw, &http.Cookie{
			Name:   m.cookieName,
			MaxAge: -1,
		})
		if !bson.IsObjectIdHex(cook.Value) {
			return auth.ErrInvalidId
		}
		return m.LoginColl.RemoveId(bson.ObjectIdHex(cook.Value))
	}

	sess, err := m.SessionMngr.Get(m.req, m.sessionName)
	if err == nil {
		// just make sure
		delete(sess.Values, "login_sid")
		sess.Options.MaxAge = -1
		return sess.Save(m.req, m.rw)
	}

	return nil
}

// ValidConfirmCode valid the code for specific key of the user specify by id.
// Re-generate or delete code for that key if need.
func (m *MgoUserManager) ValidConfirmCode(id interface{}, key, code string,
	regen, del bool) (bool, error) {
	panic("not implementd")
}

// Can uses GroupManager to determines if user have privilege to do something.
func (m *MgoUserManager) Can(user auth.User, do string) bool {
	panic("not implementd")
}

var _ auth.UserManager = &MgoUserManager{}
