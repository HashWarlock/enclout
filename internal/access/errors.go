package access

import "errors"

var (
	ErrNotFound          = errors.New("not found")
	ErrInvalidTransition = errors.New("invalid status transition")
	ErrExpired           = errors.New("expired")
)
