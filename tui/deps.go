package tui

import "context"

// Deps holds all OAuth operation callbacks the TUI delegates to the caller.
// Populate this struct in main.go and pass it to NewOAuthModel.
type Deps struct {
	LoadTokens    func() (*TokenStorage, error)
	RefreshToken  func(ctx context.Context, refreshToken string) (*TokenStorage, error)
	GenerateState func() (string, error)
	GeneratePKCE  func() (*PKCEParams, error)
	BuildAuthURL  func(state string, pkce *PKCEParams) string
	OpenBrowser   func(ctx context.Context, url string) error
	StartCallback func(ctx context.Context, port int, state string,
		exchangeFn func(context.Context, string) (*TokenStorage, error),
	) (*TokenStorage, error)
	ExchangeCode func(ctx context.Context, code, verifier string) (*TokenStorage, error)
	SaveTokens   func(storage *TokenStorage) error
	VerifyToken  func(ctx context.Context, token string) (string, error)
	MakeAPICall  func(ctx context.Context, storage *TokenStorage) error
	CallbackPort int
}
