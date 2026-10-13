package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidConfig    = errors.New("auth: configuração JWT inválida")
	ErrInvalidToken     = errors.New("auth: token inválido")
	ErrTokenExpired     = fmt.Errorf("%w: expirado", ErrInvalidToken)
	ErrTokenNotYetValid = fmt.Errorf("%w: ainda não é válido", ErrInvalidToken)
	ErrInvalidSignature = fmt.Errorf("%w: assinatura inválida ou algoritmo não permitido", ErrInvalidToken)
	ErrInvalidClaims    = fmt.Errorf("%w: claims inválidos, ausentes ou violados", ErrInvalidToken)
)

// TokenConfig define os parâmetros rigorosos que o sistema espera para gerir tokens JWT.
type TokenConfig struct {
	Secret   []byte
	Issuer   string
	Audience string
	TTL      time.Duration
	Leeway   time.Duration
	Clock    func() time.Time
}

// TokenManager encapsula de forma imutável as dependências para emitir e validar JWT.
type TokenManager struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
	leeway   time.Duration
	clock    func() time.Time
}

// Claims representa os dados que viajam abertos (codificados em base64, não criptografados) dentro do token.
type Claims struct {
	UserID    uint   `json:"user_id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	jwt.RegisteredClaims
}

// NewTokenManager inicializa o gerenciador com validação intensa de segurança.
// Assegura que falhas de design (como segredos curtos ou TTLs eternos) quebrem a aplicação logo no início.
func NewTokenManager(cfg TokenConfig) (*TokenManager, error) {
	if len(cfg.Secret) < 32 {
		return nil, fmt.Errorf("%w: o segredo deve ter no mínimo 32 bytes para proteger o HMAC-SHA256", ErrInvalidConfig)
	}
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, fmt.Errorf("%w: issuer e audience não podem estar vazios", ErrInvalidConfig)
	}
	if cfg.TTL < time.Minute || cfg.TTL > time.Hour {
		return nil, fmt.Errorf("%w: o TTL do token deve ser configurado entre 1 minuto e 1 hora", ErrInvalidConfig)
	}
	if cfg.Leeway < 0 || cfg.Leeway > 10*time.Second {
		return nil, fmt.Errorf("%w: a tolerância de dessincronização temporal (leeway) deve ser entre 0s e 10s", ErrInvalidConfig)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}

	// Copiar o segredo para prevenir que partes externas da aplicação o mutacionem em runtime.
	secretCopy := make([]byte, len(cfg.Secret))
	copy(secretCopy, cfg.Secret)

	return &TokenManager{
		secret:   secretCopy,
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		ttl:      cfg.TTL,
		leeway:   cfg.Leeway,
		clock:    cfg.Clock,
	}, nil
}

// Generate constrói, assina e emite um JWT (HS256) seguro e com identificador único.
func (m *TokenManager) Generate(userID uint, email, firstName string) (string, error) {
	now := m.clock()

	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("falha ao gerar entropia para o JTI: %w", err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiBytes)

	claims := Claims{
		UserID:    userID,
		Email:     email,
		FirstName: firstName,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Audience:  jwt.ClaimStrings{m.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("falha ao aplicar assinatura HS256: %w", err)
	}

	return signedString, nil
}

// Validate faz o processo de parse e valida as restrições estritas antes de liberar os claims.
func (m *TokenManager) Validate(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(t *jwt.Token) (interface{}, error) {
			// Defesa rigorosa contra tokens forjados com "alg: none" ou algoritmos assimétricos (RS256)
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("método de assinatura negado: inesperado %v", t.Header["alg"])
			}
			return m.secret, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience),
		jwt.WithTimeFunc(m.clock),
		jwt.WithLeeway(m.leeway),
	)

	if err != nil {
		// Mapeamento e envelopamento de erros providos pela biblioteca interna jwt/v5.
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, ErrTokenNotYetValid
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, ErrInvalidSignature
		case errors.Is(err, jwt.ErrTokenInvalidClaims), errors.Is(err, jwt.ErrTokenInvalidIssuer), errors.Is(err, jwt.ErrTokenInvalidAudience):
			return nil, ErrInvalidClaims
		default:
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
