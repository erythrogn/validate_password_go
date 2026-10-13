package auth

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const minPasswordLen = 8

var (
	ErrWeakPassword           = errors.New("password: a senha não atende aos requisitos mínimos")
	ErrPasswordTooShort       = fmt.Errorf("%w: mínimo de %d caracteres", ErrWeakPassword, minPasswordLen)
	ErrPasswordMissingLetter  = fmt.Errorf("%w: requer pelo menos uma letra", ErrWeakPassword)
	ErrPasswordMissingNumber  = fmt.Errorf("%w: requer pelo menos um número", ErrWeakPassword)
	ErrPasswordMissingSpecial = fmt.Errorf("%w: requer pelo menos um caractere especial", ErrWeakPassword)
)

// CheckStrength valida o comprimento e a presença de letras, números e símbolos na senha.
// Reaproveita os erros estruturais de formato definidos em hash.go.
func CheckStrength(password string) error {
	if len(password) == 0 {
		return ErrPasswordEmpty
	}
	if len(password) > maxBcryptLen {
		return ErrPasswordTooLong
	}
	if utf8.RuneCountInString(password) < minPasswordLen {
		return ErrPasswordTooShort
	}

	var hasLetter, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsLetter(char):
			hasLetter = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasLetter {
		return ErrPasswordMissingLetter
	}
	if !hasNumber {
		return ErrPasswordMissingNumber
	}
	if !hasSpecial {
		return ErrPasswordMissingSpecial
	}

	return nil
}

// Deprecated: Use CheckStrength para retornos padronizados sentinela. Mantida por compatibilidade estrita.
func PasswordValidation(password string) error {
	if len(password) > maxBcryptLen {
		return errors.New("senha muito longa, tente uma mais curta.")
	}

	var temLetra, temNumero, temEspecial bool
	for _, char := range password {
		switch {
		case unicode.IsLetter(char):
			temLetra = true
		case unicode.IsDigit(char):
			temNumero = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			temEspecial = true
		}
		if temLetra && temNumero && temEspecial {
			break
		}
	}

	var faltando []string
	if utf8.RuneCountInString(password) < minPasswordLen {
		faltando = append(faltando, "precisa de 8 caracteres.")
	}
	if !temLetra {
		faltando = append(faltando, "uma letra.")
	}
	if !temEspecial {
		faltando = append(faltando, "um caractere especial.")
	}
	if !temNumero {
		faltando = append(faltando, "um numero.")
	}
	if len(faltando) > 0 {
		return errors.New("a senha precisa ter: " + strings.Join(faltando, ", "))
	}

	return nil
}
