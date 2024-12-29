package main

import (
	"context"
	"crypto/sha1"
	"dagger/gcp/internal/auth"
	"dagger/gcp/internal/dagger"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type RegistryConfig struct {
	// Path to mount the secret into (a common path is ~/.docker/config.json).
	Path string

	// A user:group to set for the mounted secret.
	Owner string

	// Permission given to the mounted secret (e.g., 0600).
	Mode int

	// +private
	Gcp *Gcp
}

func (m *RegistryConfig) Mount(ctx context.Context, ctr *dagger.Container) (*dagger.Container, error) {
	c := Config{Auths: map[string]ConfigAuth{}}

	if len(m.Gcp.Registries) != 0 {
		ts, err := auth.NewTokenSource(ctx, m.Gcp.CredentialsJson, m.Gcp.WorkloadIdentityProvider, m.Gcp.WorkloadIdentityToken)
		if err != nil {
			return nil, err
		}

		token, err := ts.Token()
		if err != nil {
			return nil, err
		}

		for _, registry := range m.Gcp.Registries {
			c.Auths[registry] = ConfigAuth{
				Auth: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", "oauth2accesstoken", token.AccessToken))),
			}
		}
	}

	secret, err := c.toSecret()
	if err != nil {
		return nil, err
	}

	return ctr.WithMountedSecret(m.Path, secret, dagger.ContainerWithMountedSecretOpts{
		Owner: m.Owner,
		Mode:  m.Mode,
	}), nil
}

type Config struct {
	Auths map[string]ConfigAuth `json:"auths"`
}

type ConfigAuth struct {
	Auth string `json:"auth"`
}

func (c *Config) toSecret() (*dagger.Secret, error) {
	out, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	h := sha1.New()
	if _, err := h.Write(out); err != nil {
		return nil, err
	}

	name := fmt.Sprintf("_gcp_registry_config_%x", h.Sum(nil))

	return dag.SetSecret(name, string(out)), nil
}
