package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// maxBcryptLen define o limite seguro de bytes suportado pela implementação original do bcrypt.
const maxBcryptLen = 72

var (
	// ErrInvalidCost indica que o fator de trabalho (cost) configurado é inseguro ou excede limites.
	ErrInvalidCost = errors.New("auth: custo do bcrypt fora da faixa permitida")
	// ErrPasswordEmpty impede o processamento de entradas vazias.
	ErrPasswordEmpty = errors.New("auth: a senha não pode estar vazia")
	// ErrPasswordTooLong protege o sistema contra truncamentos silenciosos do bcrypt e ataques DoS.
	ErrPasswordTooLong = fmt.Errorf("auth: a senha excede o limite seguro de %d bytes", maxBcryptLen)
	// ErrInvalidCredentials é um erro opaco retornado ao cliente para evitar enumeração de dados.
	ErrInvalidCredentials = errors.New("auth: credenciais inválidas")
	// ErrInvalidHash indica corrupção no banco de dados, retornado sem expor detalhes internos.
	ErrInvalidHash = errors.New("auth: o formato do hash armazenado é inválido")
)

// Hash gera um hash bcrypt seguro a partir de uma senha em texto claro.
// Exige um custo mínimo de 12 para garantir robustez contra força-bruta moderna.
func Hash(password string, cost int) (string, error) {
	if cost < 12 || cost > bcrypt.MaxCost {
		return "", ErrInvalidCost
	}
	if len(password) == 0 {
		return "", ErrPasswordEmpty
	}
	if len(password) > maxBcryptLen {
		return "", ErrPasswordTooLong
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("falha interna ao gerar hash: %w", err)
	}

	return string(hashedBytes), nil
}

// Verify confere se a senha fornecida corresponde ao hash armazenado.
// Retorna erros sentinela genéricos para blindar a API contra enumeração de informações.
func Verify(hashedPassword, plainPassword string) error {
	if len(plainPassword) == 0 || len(plainPassword) > maxBcryptLen {
		return ErrInvalidCredentials
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCredentials
		}
		// Se o erro não for de incompatibilidade de senha, o hash armazenado está malformado.
		return fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	return nil
}

// DummyHash realiza um cálculo criptográfico falso utilizando os recursos da CPU.
// Use esta função no fluxo de login para mitigar ataques de enumeração por tempo (timing attacks).
// Se o usuário procurado não existir no banco, chame DummyHash com o mesmo custo usado nos usuários válidos.
func DummyHash(cost int) error {
	if cost < 12 || cost > bcrypt.MaxCost {
		return ErrInvalidCost
	}
	_, err := bcrypt.GenerateFromPassword([]byte("dummy_password_timing_mitigation"), cost)
	return err
}
