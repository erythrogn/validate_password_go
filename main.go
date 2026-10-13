package [seu pacote]

import (
	"errors"
	"log"
	"net/http"
	"time"

	"meu-projeto/auth"
)

var tokenMgr *auth.TokenManager

func iniciarSeguranca() {
	// A configuração injetada deve vir de variáveis de ambiente carregadas APENAS na main
	// através de arquivos como o .env (durante desenvolvimento) ou Secrets Injection no deploy.
	cfg := auth.TokenConfig{
		Secret:   []byte("INJETE_UMA_CHAVE_SUPER_FORTE_AQUI_DE_PONTAS"),
		Issuer:   "minha-api.empresa.com",
		Audience: "portal-web",
		TTL:      15 * time.Minute,
		Leeway:   5 * time.Second,
		Clock:    time.Now,
	}

	mgr, err := auth.NewTokenManager(cfg)
	if err != nil {
		log.Fatalf("Erro fatal na construção das políticas JWT: %v", err)
	}
	tokenMgr = mgr
}

func registroHandler(w http.ResponseWriter, r *http.Request) {
	nome := r.FormValue("nome")
	email := r.FormValue("email")
	senha := r.FormValue("senha")

	// Usamos o denylist como nil ou instanciamos um cliente HIBP externo.
	if err := auth.CheckStrength(senha, nil, nome, email); err != nil {
		// Retorno 400 mapeando o erro diretamente da sentinela.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashSeguro, err := auth.Hash(senha, 12)
	if err != nil {
		http.Error(w, "Erro interno ao processar dados sensíveis", http.StatusInternalServerError)
		return
	}

	// (Salvar hashSeguro e usuário no banco aqui...)
	w.WriteHeader(http.StatusCreated)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	senhaLivre := r.FormValue("senha")

	// (Simulação de busca ao banco de dados...)
	hashDoDB := obterHashDoBanco(email)

	if hashDoDB == "" {
		// Mitiga Timing Attacks gastando exatamente o mesmo tempo que gastaria num Match normal
		_ = auth.DummyHash(12)
		http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
		return
	}

	if err := auth.Verify(hashDoDB, senhaLivre); err != nil {
		http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
		return
	}

	token, err := tokenMgr.Generate(1, email, "Usuário")
	if err != nil {
		http.Error(w, "Falha ao assinar requisição", http.StatusInternalServerError)
		return
	}

	// Retorna usando padrão stateful/seguro.
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_sess",
		Value:    token,
		Path:     "/",
		HttpOnly: true,                 // Previne acesso pelo JS client-side.
		Secure:   true,                 // Exige transmissão HTTPS.
		SameSite: http.SameSiteLaxMode, // Proteção contra requisições CSRF.
	})

	w.WriteHeader(http.StatusOK)
}

func protegidaHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_sess")
	if err != nil {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}

	claims, err := tokenMgr.Validate(cookie.Value)
	if err != nil {
		// Em caso de alerta severo (assinatura errada, alg none), enviamos o `%w` aos logs silenciosamente:
		log.Printf("alerta de seguranca (interceptacao ou alteracao?): %v", err)

		// Resposta refinada na camada de rede voltada ao cliente
		if errors.Is(err, auth.ErrTokenExpired) {
			http.Error(w, "Sessão encerrada por inatividade. Faça login novamente.", http.StatusUnauthorized)
			return
		}

		http.Error(w, "Sessão inválida", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Área restrita alcançada com sucesso. Olá, " + claims.FirstName))
}
