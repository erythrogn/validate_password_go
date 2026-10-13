package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestHash(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		password    string
		cost        int
		wantHashErr error
	}{
		{"Valid Parameters", "SecureP@ssw0rd123!", 12, nil},
		{"Empty Password", "", 12, ErrPasswordEmpty},
		{"Exceeds 72 bytes limit", strings.Repeat("a", 73), 12, ErrPasswordTooLong},
		{"Exact 72 bytes boundary", strings.Repeat("a", 72), 12, nil},
		{"Cost Below Floor", "SecureP@ssw0rd123!", 11, ErrInvalidCost},
		{"Cost Above Ceiling", "SecureP@ssw0rd123!", bcrypt.MaxCost + 1, ErrInvalidCost},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Hash(tt.password, tt.cost)
			if !errors.Is(err, tt.wantHashErr) {
				t.Fatalf("esperado %v, obtido %v", tt.wantHashErr, err)
			}
		})
	}
}

func TestVerifyAndDummy(t *testing.T) {
	t.Parallel()
	validHash, _ := Hash("SecureP@ssw0rd123!", 12)

	t.Run("Verify Credentials", func(t *testing.T) {
		if err := Verify(validHash, "SecureP@ssw0rd123!"); err != nil {
			t.Errorf("senha correta rejeitada: %v", err)
		}
		if err := Verify(validHash, "WrongPassword123!"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("senha incorreta não retornou ErrInvalidCredentials")
		}
		if err := Verify("not-a-hash", "SecureP@ssw0rd123!"); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("hash malformado não retornou ErrInvalidHash")
		}
		if err := Verify(validHash, ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("senha vazia na verificação não retornou ErrInvalidCredentials")
		}
		if err := Verify(validHash, strings.Repeat("a", 73)); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("senha superdimensionada não retornou ErrInvalidCredentials")
		}
	})

	t.Run("DummyHash", func(t *testing.T) {
		if err := DummyHash(11); !errors.Is(err, ErrInvalidCost) {
			t.Errorf("DummyHash deve rejeitar custos fora da faixa")
		}
		if err := DummyHash(12); err != nil {
			t.Errorf("DummyHash com custo válido falhou: %v", err)
		}
	})
}

// mockDenylist simula um serviço externo que contém senhas banidas.
type mockDenylist struct {
	banned []string
}

func (m *mockDenylist) Contains(pwd string) bool {
	for _, b := range m.banned {
		if b == pwd {
			return true
		}
	}
	return false
}

func TestCheckStrength(t *testing.T) {
	t.Parallel()
	dl := &mockDenylist{banned: []string{"StrongP@ssw0rd1!"}}

	tests := []struct {
		name       string
		password   string
		userInputs []string
		wantErr    error
	}{
		{"Strong Valid Password", "MyS3cur3!Password", nil, nil},
		{"Too Short", "MyS3c!r0", nil, ErrPasswordTooShort},
		{"Missing Upper", "mys3cur3!password", nil, ErrPasswordMissingUpper},
		{"Missing Lower", "MYS3CUR3!PASSWORD", nil, ErrPasswordMissingLower},
		{"Missing Number", "MySecure!Password", nil, ErrPasswordMissingNumber},
		{"Missing Special", "MyS3cur3Password", nil, ErrPasswordMissingSpecial},
		{"Control Char Present", "MyS3cur3!Passw\nrd", nil, ErrPasswordHasControl},
		{"Leading Space", " MyS3cur3!Password", nil, ErrPasswordHasSpaces},
		{"Trailing Space", "MyS3cur3!Password ", nil, ErrPasswordHasSpaces},
		{"Contains User Name", "HelloJohnS3cur3!", []string{"John"}, ErrPasswordContainsUser},
		{"Contains User Email Case Insensitive", "john@mail.comS3cur3!", []string{"JOHN@mail.com"}, ErrPasswordContainsUser},
		{"In Denylist", "StrongP@ssw0rd1!", nil, ErrPasswordInDenylist},
		{"Exact 72 bytes valid", "MyS3cur3!Password" + strings.Repeat("A", 55), nil, nil},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckStrength(tt.password, dl, tt.userInputs...)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("esperado %v, obtido %v", tt.wantErr, err)
			}
		})
	}
}

func TestJWTValidations(t *testing.T) {
	t.Parallel()
	frozenTime := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return frozenTime }
	validSecret := []byte(strings.Repeat("a", 32))
	shortSecret := []byte(strings.Repeat("a", 31))

	t.Run("Construct Constraints", func(t *testing.T) {
		t.Parallel()
		_, err := NewTokenManager(TokenConfig{Secret: shortSecret, Issuer: "I", Audience: "A", TTL: 15 * time.Minute, Leeway: 0, Clock: clock})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("deveria recusar segredo de 31 bytes")
		}
		_, err = NewTokenManager(TokenConfig{Secret: validSecret, Issuer: "", Audience: "A", TTL: 15 * time.Minute, Leeway: 0, Clock: clock})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("deveria recusar issuer vazio")
		}
		_, err = NewTokenManager(TokenConfig{Secret: validSecret, Issuer: "I", Audience: "A", TTL: 50 * time.Second, Leeway: 0, Clock: clock})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("deveria recusar TTL abaixo de 1 min")
		}
	})

	manager, _ := NewTokenManager(TokenConfig{
		Secret:   validSecret,
		Issuer:   "auth-server",
		Audience: "client-app",
		TTL:      15 * time.Minute,
		Leeway:   0,
		Clock:    clock,
	})

	t.Run("Standard Issue and Validation", func(t *testing.T) {
		token, err := manager.Generate(123, "user@mail.com", "User")
		if err != nil {
			t.Fatalf("falha inesperada ao gerar token: %v", err)
		}
		claims, err := manager.Validate(token)
		if err != nil || claims.UserID != 123 {
			t.Fatalf("falha ao validar token correto ou perda de dados: %v", err)
		}
	})

	t.Run("Forged alg:none and Tampering", func(t *testing.T) {
		token, _ := manager.Generate(123, "user@mail.com", "User")
		parts := strings.Split(token, ".")

		// 1. Testando Bypass de Assinatura (alg: none)
		forgedToken := parts[0] + "." + parts[1] + "."
		if _, err := manager.Validate(forgedToken); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("token forjado com alg:none passou na validação")
		}

		// 2. Testando Payload Adulterado
		tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"user_id": 999}`))
		tamperedToken := parts[0] + "." + tamperedPayload + "." + parts[2]
		if _, err := manager.Validate(tamperedToken); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("token com assinatura quebrada passou na validação")
		}
	})

	t.Run("Time and Claims Validations", func(t *testing.T) {
		token, _ := manager.Generate(123, "u@m.com", "U")

		// Avança exatamente para a fronteira da expiração (Expirado por 1 ms)
		futureClock := func() time.Time { return frozenTime.Add(15 * time.Minute).Add(time.Millisecond) }
		futureManager, _ := NewTokenManager(TokenConfig{
			Secret: validSecret, Issuer: "auth-server", Audience: "client-app", TTL: 15 * time.Minute, Leeway: 0, Clock: futureClock,
		})

		if _, err := futureManager.Validate(token); !errors.Is(err, ErrTokenExpired) {
			t.Errorf("token vencido não retornou ErrTokenExpired")
		}

		// Retrocede para simular NBF no futuro (Early usage)
		pastClock := func() time.Time { return frozenTime.Add(-1 * time.Minute) }
		pastManager, _ := NewTokenManager(TokenConfig{
			Secret: validSecret, Issuer: "auth-server", Audience: "client-app", TTL: 15 * time.Minute, Leeway: 0, Clock: pastClock,
		})

		if _, err := pastManager.Validate(token); !errors.Is(err, ErrTokenNotYetValid) {
			t.Errorf("token usado antes da hora não retornou ErrTokenNotYetValid")
		}

		// Erro de Audience/Issuer
		wrongAudManager, _ := NewTokenManager(TokenConfig{
			Secret: validSecret, Issuer: "auth-server", Audience: "another-app", TTL: 15 * time.Minute, Leeway: 0, Clock: clock,
		})

		if _, err := wrongAudManager.Validate(token); !errors.Is(err, ErrInvalidClaims) {
			t.Errorf("audience errado não acionou ErrInvalidClaims")
		}

		// Erro de Secret Errado
		wrongSecretManager, _ := NewTokenManager(TokenConfig{
			Secret: []byte(strings.Repeat("b", 32)), Issuer: "auth-server", Audience: "client-app", TTL: 15 * time.Minute, Leeway: 0, Clock: clock,
		})
		if _, err := wrongSecretManager.Validate(token); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("segredo errado não acionou ErrInvalidSignature")
		}
	})
}

func BenchmarkHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Hash("BenchmarkP@ssw0rd123!", 12)
	}
}

func BenchmarkVerify(b *testing.B) {
	h, _ := Hash("BenchmarkP@ssw0rd123!", 12)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(h, "BenchmarkP@ssw0rd123!")
	}
}
