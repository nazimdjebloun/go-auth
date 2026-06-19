package goauth

import (
	"context"
	"fmt"
	"net/smtp"
)

type SMTPMailer struct {
	host string
	port int
	user string
	pass string
	from string
}

func NewSMTPMailer(cfg SMTPConfig, from string) *SMTPMailer {
	return &SMTPMailer{
		host: cfg.Host,
		port: cfg.Port,
		user: cfg.User,
		pass: cfg.Pass,
		from: from,
	}
}

func (m *SMTPMailer) Send(ctx context.Context, to, subject, body string) error {
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n%s",
		m.from, to, subject, body)

	auth := smtp.PlainAuth("", m.user, m.pass, m.host)
	addr := fmt.Sprintf("%s:%d", m.host, m.port)

	return smtp.SendMail(addr, auth, m.from, []string{to}, []byte(msg))
}
