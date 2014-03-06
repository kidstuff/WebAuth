package mgoauth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"github.com/gorilla/securecookie"
	"github.com/kidstuff/WebAuth/auth"
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
	dbsess   *mgo.Session
	UserColl *mgo.Collection
	gMngr    auth.GroupManager
	Formater FormatChecker
}

// SetGroupManager sets GroupManager use for the Can method.
func (m *MgoUserManager) SetGroupManager(mngr auth.GroupManager) {
	m.gMngr = mngr
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
	if ok && bson.IsObjectIdHex(sid) {
		return m.UserColl.RemoveId(m.UserColl.RemoveId(bson.ObjectIdHex(sid)))
	}
	return auth.ErrInvalidId
}

// GetUser gets the infomations and update the LastActivity of the current
// Loged user;
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) GetUser() (auth.User, error) {
	panic("not implementd")
}

// FindUser finds the user with the given id;
// Its returns an ErrNotFound if the user's id was not found.
func (m *MgoUserManager) FindUser(id interface{}) (auth.User, error) {
	panic("not implementd")
}

// FindUserByEmail like FindUser but receive an email
func (m *MgoUserManager) FindUserByEmail(email string) (auth.User, error) {
	panic("not implementd")
}

// FindAllUser finds and return a slice of user.
// offsetId, limit define which sub-sequence of matching users to return.
// Limit take an number of user per page; offsetId take the Id of the last
// user of the previous page.
func (m *MgoUserManager) FindAllUser(offsetId interface{}, limit int) (
	[]auth.User, error) {
	panic("not implementd")
}

// FindAllUserOline finds and return a slice of current Loged user.
// See FindAllUser for the usage.
func (m *MgoUserManager) FindAllUserOnline(offsetId interface{}, limit int) (
	[]auth.User, error) {
	panic("not implementd")
}

// CountUserOnline counts the number of user current Loged.
// It counts the user that LastActivity+OnlineThreshold<Now.
func (m *MgoUserManager) CountUserOnline() int {
	panic("not implementd")
}

// ValidateUser validate user email and password.
// It returns the user infomations if the email and password is correct.
func (m *MgoUserManager) ValidateUser(r *http.Request) (auth.User, error) {
	panic("not implementd")
}

// Login logs user in by using a session that store user id.
// Stay take a number of second to keep the user Login state.
func (m *MgoUserManager) Login(id interface{}, stay int) error {
	panic("not implementd")
}

// Logout logs the current user out.
func (m *MgoUserManager) Logout() error {
	panic("not implementd")
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
