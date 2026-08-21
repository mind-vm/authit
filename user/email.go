package user

import "context"

// EmailSender delivers the links/codes authit's flows generate. authit
// ships no concrete implementation; host applications wire in whatever
// sends mail (SMTP, a queue, a transactional-email API, ...).
type EmailSender interface {
	SendPasswordReset(ctx context.Context, email, token string) error
	SendEmailVerification(ctx context.Context, email, token string) error
}

// NoopEmailSender discards every message. Useful for tests, or apps that
// deliver verification/reset links out of band.
type NoopEmailSender struct{}

func (NoopEmailSender) SendPasswordReset(ctx context.Context, email, token string) error {
	return nil
}

func (NoopEmailSender) SendEmailVerification(ctx context.Context, email, token string) error {
	return nil
}
