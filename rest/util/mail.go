package util

import (
	"errors"
	"github.com/kidstuff/WebAuth/rest/config"
	"net/smtp"
)

func SendSimpleMail(c config.Configurator, to, subject, message string) error {
	identity, err := c.Get("smtp_identity")
	if err != nil {
		return errors.New("util: cannot load config 'smtp_identity' for sending mail")
	}

	username, err := c.Get("smtp_username")
	if err != nil {
		return errors.New("util: cannot load config 'smtp_username' for sending mail")
	}

	password, err := c.Get("smtp_password")
	if err != nil {
		return errors.New("util: cannot load config 'smtp_password' for sending mail")
	}

	host, err := c.Get("smtp_host")
	if err != nil {
		return errors.New("util: cannot load config 'smtp_host' for sending mail")
	}

	port, err := c.Get("smtp_port")
	if err != nil {
		return errors.New("util: cannot load config 'smtp_port' for sending mail")
	}

	// Set up authentication information.
	auth := smtp.PlainAuth(
		identity,
		username,
		password,
		host,
	)

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	return smtp.SendMail(
		host+":"+port,
		auth,
		username,
		[]string{to},
		[]byte("Subject: "+subject+"\r\n\r\n"+message),
	)
}
