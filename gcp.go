package main

import (
	"context"
	"dagger/gcp/internal/auth"
	"dagger/gcp/internal/dagger"
	"encoding/json"
	"errors"
	"fmt"
)

func New(
	// +optional
	credentialsJson *dagger.Secret,
	// +optional
	workloadIdentityProvider string,
	// +optional
	workloadIdentityToken *dagger.Secret,
	// +optional
	registries []string,
) (*Gcp, error) {

	if credentialsJson == nil && workloadIdentityToken == nil {
		return nil, errors.New("no credentials or workload identity token specified")
	}

	if workloadIdentityToken != nil && credentialsJson == nil && workloadIdentityProvider == "" {
		return nil, errors.New("workload identity provider must be specified")
	}

	gcp := &Gcp{
		CredentialsJson:          credentialsJson,
		WorkloadIdentityProvider: workloadIdentityProvider,
		WorkloadIdentityToken:    workloadIdentityToken,
		Registries:               registries,
	}

	return gcp, nil
}

type Gcp struct {
	// +private
	CredentialsJson *dagger.Secret

	// +private
	WorkloadIdentityProvider string

	// +private
	WorkloadIdentityToken *dagger.Secret

	// +private
	Registries []string
}

func (m *Gcp) Mount(ctr *dagger.Container) *dagger.Container {
	if m.CredentialsJson != nil {
		return ctr.
			WithEnvVariable("GOOGLE_APPLICATION_CREDENTIALS", "/.gcp/credentials").
			WithEnvVariable("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "/.gcp/credentials").
			WithMountedSecret("/.gcp/credentials", m.CredentialsJson)
	}

	if m.WorkloadIdentityProvider != "" && m.WorkloadIdentityToken != nil {
		credentialsJson, err := auth.ExternalAccountCredentialsJson(m.WorkloadIdentityProvider, "/.gcp/token")
		if err != nil {
			return ctr
		}

		return ctr.
			WithEnvVariable("GOOGLE_APPLICATION_CREDENTIALS", "/.gcp/credentials").
			WithEnvVariable("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "/.gcp/credentials").
			WithNewFile("/.gcp/credentials", credentialsJson).
			WithMountedSecret("/.gcp/token", m.WorkloadIdentityToken)
	}

	return ctr
}

func (m *Gcp) RegistryAuth(ctx context.Context, ctr *dagger.Container) (*dagger.Container, error) {
	token, err := m.GetAccessToken(ctx, "text")
	if err != nil {
		return nil, err
	}

	c := ctr
	for _, registry := range m.Registries {
		c = c.WithRegistryAuth(registry, "oauth2accesstoken", token)
	}

	return c, nil
}

func (m *Gcp) RegistryConfig(
	path string,
	// +optional
	owner string,
	// +optional
	mode int,
) (*RegistryConfig, error) {
	return &RegistryConfig{Path: path, Owner: owner, Mode: mode, Gcp: m}, nil
}

func (m *Gcp) GetAccessToken(
	ctx context.Context,
	// +optional
	// +default="text"
	format string,
) (*dagger.Secret, error) {
	if format != "json" && format != "text" {
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	ts, err := auth.NewTokenSource(ctx, m.CredentialsJson, m.WorkloadIdentityProvider, m.WorkloadIdentityToken)
	if err != nil {
		return nil, err
	}

	token, err := ts.Token()
	if err != nil {
		return nil, err
	}

	if format == "text" {
		return dag.SetSecret("_gcp_access_token", token.AccessToken), nil
	}

	tokenJson, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}

	return dag.SetSecret("_gcp_json_access_token", string(tokenJson)), nil
}
