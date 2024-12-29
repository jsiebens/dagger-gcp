package auth

import (
	"context"
	"dagger/gcp/internal/dagger"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/google/externalaccount"
)

const (
	CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

func ExternalAccountCredentialsJson(workloadIdentityProvider string, file string) (string, error) {
	values := map[string]any{
		"universe_domain":    "googleapis.com",
		"type":               "external_account",
		"audience":           workloadIdentityProvider,
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"token_url":          "https://sts.googleapis.com/v1/token",
		"credential_source": map[string]any{
			"file": file,
			"format": map[string]any{
				"type": "text",
			},
		},
	}

	credentialsJson, err := json.Marshal(values)
	if err != nil {
		return "", err
	}

	return string(credentialsJson), nil
}

func NewTokenSource(
	ctx context.Context,
	credentialsJson *dagger.Secret,
	workloadIdentityProvider string,
	workloadIdentityToken *dagger.Secret) (oauth2.TokenSource, error) {

	if credentialsJson != nil {
		return createTokenSourceFromCredentials(ctx, credentialsJson)
	}

	if workloadIdentityProvider != "" && workloadIdentityToken != nil {
		return createExternalAccountTokenSource(ctx, workloadIdentityProvider, workloadIdentityToken)
	}

	return nil, errors.New("no valid credentials found")
}

func createTokenSourceFromCredentials(ctx context.Context, credentialsSecret *dagger.Secret) (oauth2.TokenSource, error) {
	credentialsJson, err := credentialsSecret.Plaintext(ctx)
	if err != nil {
		return nil, err
	}

	credentials, err := google.CredentialsFromJSON(ctx, []byte(credentialsJson), CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	return credentials.TokenSource, nil
}

func createExternalAccountTokenSource(ctx context.Context, workloadIdentityProvider string, workloadIdentityToken *dagger.Secret) (oauth2.TokenSource, error) {
	c := externalaccount.Config{
		Audience:             workloadIdentityProvider,
		SubjectTokenType:     "urn:ietf:params:oauth:token-type:jwt",
		SubjectTokenSupplier: &secretTokenSupplier{s: workloadIdentityToken},
		Scopes:               []string{CloudPlatformScope},
	}

	return externalaccount.NewTokenSource(ctx, c)
}

type secretTokenSupplier struct {
	s *dagger.Secret
}

func (s *secretTokenSupplier) SubjectToken(ctx context.Context, _ externalaccount.SupplierOptions) (string, error) {
	return s.s.Plaintext(ctx)
}
