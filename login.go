package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"github.com/chef/go-chef"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathLogin(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"node_name": {
			Type:        framework.TypeString,
			Description: "The node name, can be often found at /etc/chef/client.rb.",
		},
		"private_key": {
			Type:        framework.TypeString,
			Description: "The private key, can be often found at /etc/chef/client.pem.",
		},
		"signed_string": {
			Type:        framework.TypeString,
			Description: "A string signed by the node's private key.",
		},
	}
	callbks := map[logical.Operation]framework.OperationFunc{
		logical.UpdateOperation: b.pathAuthLogin,
	}
	return []*framework.Path{{
		Pattern:   "login",
		Fields:    fields,
		Callbacks: callbks,
	},
		{
			Pattern:   "login/" + framework.GenericNameRegex("node_name"),
			Fields:    fields,
			Callbacks: callbks,
		},
	}
}

func (b *backend) Login(ctx context.Context, req *logical.Request, nodeName, privateKey, signedString string) (*logical.Response, error) {
	l := b.Logger().With("node_name", nodeName, "request", req.ID)

	l.Info("login attempt", "node_name", nodeName)

	b.RLock()
	defer b.RUnlock()

	raw, err := req.Storage.Get(ctx, "config")
	if err != nil {
		l.Error("error occured while get chef host config", "error", err)
		return logical.ErrorResponse(fmt.Sprintf("Error while fetching config : %s", err)), err
	}

	if raw == nil {
		l.Warn("clients should not use an unconfigured backend.")
		return logical.ErrorResponse("no host configured"), nil
	}

	conf := &config{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	}

	chefUserName := nodeName

	if privateKey == "" {
		privateKey = conf.PrivateKeyPem
		chefUserName = conf.UserName
	}

	client, err := chef.NewClient(&chef.Config{
		Name:    chefUserName,
		Key:	 privateKey,
		BaseURL: conf.Host,
		SkipSSL: true,
		Timeout: 10,
	})
	if err != nil {
		return nil, err
	}

	if signedString != "" {
		nodeClient, err := client.Clients.Get(nodeName)
		if err != nil {
			l.Error("error getting client info from chef", "client", nodeClient, "error", err)
			return nil, logical.ErrPermissionDenied
		}

		clientPubKey := []byte(nodeClient.PublicKey)
		block, _ := pem.Decode(clientPubKey)
		if block == nil || block.Type != "PUBLIC KEY" {
			l.Error("failed to decode PEM block containing chef client public key")
			return nil, err
		}
		parsedClientPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			l.Error("error parsing chef client public key:", err)
			return nil, err
		}
		validClientPubKey, _ := parsedClientPubKey.(*rsa.PublicKey)

		decodedSignedString, err := base64.StdEncoding.DecodeString(signedString)
		if err != nil {
			l.Error("error decoding signed string:", err)
			return nil, err
		}

		hashedSignedMessage := sha256.Sum256([]byte(nodeName))

		err = rsa.VerifyPKCS1v15(validClientPubKey, crypto.SHA256, hashedSignedMessage[:], decodedSignedString)
		if err != nil {
			l.Error("error verificating client:", err)
			return nil, err
		} else {
			l.Info("client verification successful")
		}
	}

	node, err := client.Nodes.Get(nodeName)
	if err != nil {
		l.Error("error occured while authentication chef host with", "host", conf.Host, "error", err)
		return nil, logical.ErrPermissionDenied
	}

	var auth *logical.Auth

	var chefPolicy *ChefPolicy
	if err != nil {
		l.Error("error while fetching chef policy list from storage", "error", err)
		return nil, err
	}
	if node.PolicyName != "" {
		chefPolicies, err := b.getPolicyList(ctx, req)
		l = l.With("policy", node.PolicyName)
		for _, p := range chefPolicies {
			if p == node.PolicyName {
				chefPolicy, err = b.getPolicyEntryFromStorage(ctx, req, p)
				if err != nil {
					l.Error("error while fetching chef policy from storage", "policy", p, "error", err)
					return nil, err
				}
				if chefPolicy == nil {
					l.Error("can't fetch a listed chef policy in storage", "policy", p)
					return nil, fmt.Errorf("cannot fetch chef policy %s from storage backend", p)
				}
				auth = &logical.Auth{
					DisplayName:  nodeName,
					LeaseOptions: logical.LeaseOptions{TTL: chefPolicy.TTL, MaxTTL: chefPolicy.MaxTTL, Renewable: true},
					Period:       chefPolicy.Period,
					Policies:     append(chefPolicy.VaultPolicies, "default"),
					Metadata:     map[string]string{"policy": chefPolicy.Name, "node_name": nodeName},
					GroupAliases: []*logical.Alias{
						{
							Name: "policy-" + chefPolicy.Name,
						},
					},
					InternalData: map[string]interface{}{"private_key": privateKey},
				}
				break
			}
		}
	} else if nodeRolesNames := node.AutomaticAttributes["roles"].([]interface{}); nodeRolesNames != nil && len(nodeRolesNames) > 0 {
		nodeRoles := make([]string, 0, len(nodeRolesNames))
		chefRoles, err := b.getRoleList(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, nRaw := range nodeRolesNames {

			roleName, ok := nRaw.(string)
			if !ok {
				return nil, fmt.Errorf("Can't serialize role name %+v into a string", nRaw)
			}
			nodeRoles = append(nodeRoles, roleName)
		}
		auth, err = func() (*logical.Auth, error) {
			for _, r := range nodeRoles {
				for _, cr := range chefRoles {

					if r == cr {
						l = l.With("role", r)
						chefRole, err := b.getRoleEntryFromStorage(ctx, req, r)
						if err != nil {
							l.Error("error while fetching chef role from storage", "role", r, "error", err)
							return nil, err
						}
						if chefRole == nil {
							l.Error("can't fetch a listed chef role in storage", "role", r)
							return nil, fmt.Errorf("cannot fetch chef role %s from storage backend", r)
						}
						auth := &logical.Auth{
							DisplayName:  nodeName,
							LeaseOptions: logical.LeaseOptions{TTL: chefRole.TTL, MaxTTL: chefRole.MaxTTL, Renewable: true},
							Period:       chefRole.Period,
							Policies:     append(chefRole.VaultPolicies, "default"),
							Metadata:     map[string]string{"role": chefRole.Name, "node_name": nodeName},
							GroupAliases: []*logical.Alias{},
							InternalData: map[string]interface{}{"private_key": privateKey},
						}
						// n is usually between 1 or 5, it's ok to loop again
						for _, r := range nodeRoles {
							auth.GroupAliases = append(auth.GroupAliases, &logical.Alias{Name: "role" + r})
						}
						return auth, nil
					}
				}
			}
			return nil, nil
		}()
		if err != nil {
			return nil, err
		}
	}

	// default login
	if auth == nil {
		auth = &logical.Auth{
			DisplayName:  nodeName,
			LeaseOptions: logical.LeaseOptions{TTL: conf.DefaultTTL, MaxTTL: conf.DefaultMaxTTL, Renewable: true},
			Period:       conf.DefaultPeriod,
			Policies:     []string{"default"},
			Metadata:     map[string]string{"node_name": nodeName},
			GroupAliases: []*logical.Alias{},
			InternalData: map[string]interface{}{"private_key": privateKey},
		}
	}

	if len(conf.DefaultPolicies) > 0 {
		auth.Policies = append(auth.Policies, conf.DefaultPolicies...)
	}

	policies, searches, err := b.MatchingSearches(req, client)
	if err != nil {
		l.Error(fmt.Sprintf("error while fetching matched searches: %s", err))
		return nil, err
	}
	if len(searches) > 0 {
		auth.Metadata["chef-matched-searches"] = strings.Join(searches, ",")
	}
	if len(policies) > 0 {
		auth.Policies = append(auth.Policies, policies...)
	}

	l.Info("login successful", "node_name", nodeName)

	return &logical.Response{Auth: auth}, nil
}

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nodeName := d.Get("node_name").(string)
	if nodeName == "" {
		return logical.ErrorResponse("no node name provided"), nil
	}

	privateKey := d.Get("private_key").(string)
	signedString := d.Get("signed_string").(string)
	if privateKey == "" && signedString == "" {
		return logical.ErrorResponse("no private key or signed string provided"), nil
	}

	return b.Login(ctx, req, nodeName, privateKey, signedString)
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	b.Logger().Debug("received a renew request for %s", req.Auth.DisplayName)

	nodeName := req.Auth.Metadata["node_name"]
	if nodeName == "" {
		return logical.ErrorResponse("no node name provided"), nil
	}

	privateKeyRaw, ok := req.Auth.InternalData["private_key"]
	var privateKey string
	if ok {
		privateKey = privateKeyRaw.(string)
	}
	signedStringRaw, ok := req.Auth.InternalData["signed_string"]
	var signedString string
	if ok {
		signedString = signedStringRaw.(string)
	}
	if privateKey == "" && signedString == "" {
		return logical.ErrorResponse("no private key or signed string`` found"), nil
	}

	return b.Login(ctx, req, nodeName, privateKey, signedString)
}
