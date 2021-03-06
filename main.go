package main

import (
	"context"
	stdlog "log"
	"os"
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		stdlog.Fatal(err)
	}
}

// Factory is a factory for a logical backend
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	sync.RWMutex
	SearchStore *sync.Map
}

// Backend is the factory for our backend
func Backend(_ *logical.BackendConfig) *backend {
	var b backend

	b.SearchStore = &sync.Map{}
	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login*"},
			SealWrapStorage: []string{"config"},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(&b),
			},
			pathLogin(&b),
			pathRole(&b),
			pathPolicy(&b),
			pathSearch(&b),
		),
	}

	logger := logging.NewVaultLoggerWithWriter(os.Stderr, log.Debug)
	b.Backend.Setup(context.Background(), &logical.BackendConfig{
		Logger: logger,
	})

	return &b
}
