# auth

Pacote de autenticação em Go focado em segurança. Implementa hash de senhas com bcrypt, gerenciamento de tokens JWT (HS256) e validação de força de senha.

A principal regra do pacote é não depender de variáveis de ambiente (`os.Getenv`) ou estado global. Toda a configuração precisa ser injetada na inicialização.

## O que o pacote faz

* **JWT (HS256):** Gera e valida tokens. Bloqueia ativamente tentativas de bypass (como `alg: none`), exige as claims de tempo (`exp`, `nbf`, `iat`) e gera um `jti` único automaticamente.
* **Hash (bcrypt):** Aplica um custo mínimo de 12 e corta senhas maiores que 72 bytes antes do processamento (evitando bugs e comportamentos inesperados do algoritmo). Inclui um `DummyHash` para evitar timing attacks em rotas de login.
* **Senhas:** Valida regras mínimas (12 caracteres, letras, números, símbolos), barra caracteres de controle e impede que o usuário use o próprio nome/email na senha. Aceita integração com denylists.
* **Erros:** Retorna apenas erros sentinela (ex: `auth.ErrInvalidCredentials`), ocultando os detalhes da validação para a ponta, mas permitindo log detalhado internamente via `%w`.

## Como usar

### 1. Configurando o JWT

Como não usamos estado global, crie a configuração na inicialização da sua aplicação e passe o gerenciador para os seus handlers.

```go
package main

import (
	"log"
	"time"
	"seuprojeto/auth"
)

func main() {
	cfg := auth.TokenConfig{
		Secret:   []byte("chave-com-pelo-menos-32-bytes-aqui"),
		Issuer:   "minha-api",
		Audience: "meu-front",
		TTL:      30 * time.Minute,
		Leeway:   5 * time.Second,
		Clock:    time.Now,
	}

	tokenMgr, err := auth.NewTokenManager(cfg)
	if err != nil {
		log.Fatal(err)
	}
	
	// Repasse o tokenMgr para as rotas que precisam emitir ou validar tokens.
}

```

### 2. Validação e Hash de Senha

Validando no momento do cadastro:

```go
senha := "S3nh@Forte!2026"
nome := "Carlos"
email := "carlos@email.com"

// O pacote valida a força da senha e garante que nome/email não estão contidos nela.
// O segundo argumento aceita uma interface para denylist (pode passar nil se não usar).
if err := auth.CheckStrength(senha, nil, nome, email); err != nil {
    // Retorna erro sentinela, seguro para devolver ao usuário final
    return err 
}

hash, err := auth.Hash(senha, 12)
if err != nil {
    log.Fatal(err)
}

```

### 3. Login e prevenção de Timing Attacks

```go
// Simulando busca no banco
hashSalvo := buscarHashDoUsuario(email)

if hashSalvo == "" {
    // Usuário não existe. Roda o DummyHash para a requisição demorar
    // o mesmo tempo que demoraria se o usuário existisse.
    _ = auth.DummyHash(12)
    return errors.New("credenciais inválidas")
}

if err := auth.Verify(hashSalvo, senhaDigitada); err != nil {
    return errors.New("credenciais inválidas")
}

// Login válido, gerar token
token, err := tokenMgr.Generate(123, email, "Carlos")

```

### 4. Validando o Token (Rotas Protegidas)

```go
claims, err := tokenMgr.Validate(tokenRecebido)
if err != nil {
    if errors.Is(err, auth.ErrTokenExpired) {
        return errors.New("token expirado")
    }
    return errors.New("acesso negado")
}

fmt.Println("Usuário logado:", claims.UserID)

```

## Check-list para Produção

Este pacote resolve a parte lógica, mas a aplicação que o consome precisa garantir:

* **Injeção do Segredo:** O `Secret` do JWT deve vir de um gerenciador de segredos (Vault, AWS Secrets) ou variável de ambiente lida apenas na `main`. Nunca commite a chave no código.
* **Rate Limiting:** O `bcrypt` com custo 12 ou mais vai consumir CPU intencionalmente. Coloque um limitador de requisições (rate limit) nas rotas de login/cadastro para evitar negação de serviço (DoS).
* **Cookies e HTTPS:** Se for devolver o token para web, devolva através de um cookie configurado com `HttpOnly`, `Secure` e `SameSite=Lax`. O tráfego precisa ser exclusivamente HTTPS.
* **Logout/Revogação:** O pacote gera um ID único para cada token (`jti`). Como o JWT é *stateless*, para fazer logout antes do tempo expirar, você precisa extrair esse ID, salvá-lo no Redis (blocklist) e validar nas suas rotas.
