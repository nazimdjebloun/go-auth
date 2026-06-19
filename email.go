package goauth

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/nazimdjebloun/go-auth/port"
)

type smtpEmailSender struct {
	host string
	port int
	user string
	pass string
	from string
}

func NewSMTPEmailSender(cfg SMTPConfig, from string) *smtpEmailSender {
	return &smtpEmailSender{
		host: cfg.Host,
		port: cfg.Port,
		user: cfg.User,
		pass: cfg.Pass,
		from: from,
	}
}

func (s *smtpEmailSender) Send(ctx context.Context, data port.EmailData) error {
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n%s",
		s.from, data.To, data.Subject, data.HTML)

	if data.HTML == "" {
		msg = fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
			s.from, data.To, data.Subject, data.Text)
	}

	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	return smtp.SendMail(addr, auth, s.from, []string{data.To}, []byte(msg))
}
