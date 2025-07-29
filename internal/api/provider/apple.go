package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const DefaultAppleIssuer = "https://appleid.apple.com"
const OtherAppleIssuer = "https://account.apple.com"

func IsAppleIssuer(issuer string) bool {
	return issuer == DefaultAppleIssuer || issuer == OtherAppleIssuer
}

func DetectAppleIDTokenIssuer(ctx context.Context, idToken string) (string, error) {
	var payload struct {
		Issuer string `json:"iss"`
	}

	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("apple: invalid ID token")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("apple: invalid ID token %w", err)
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("apple: invalid ID token %w", err)
	}

	return payload.Issuer, nil
}

// AppleProvider stores the custom config for apple provider
type AppleProvider struct {
	*oauth2.Config
	oidc *oidc.Provider
	
	// JWT相关字段
	jwtGenerator *AppleJWTGenerator
	teamID       string
	keyID        string
	currentSecret string
	secretMutex   sync.RWMutex
	lastGenerated time.Time
}

type IsPrivateEmail bool

// Apple returns an is_private_email field that could be a string or boolean value so we need to implement a custom unmarshaler
// https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
func (b *IsPrivateEmail) UnmarshalJSON(data []byte) error {
	var boolVal bool
	if err := json.Unmarshal(data, &boolVal); err == nil {
		*b = IsPrivateEmail(boolVal)
		return nil
	}

	// ignore the error and try to unmarshal as a string
	var strVal string
	if err := json.Unmarshal(data, &strVal); err != nil {
		return err
	}

	var err error
	boolVal, err = strconv.ParseBool(strVal)
	if err != nil {
		return err
	}

	*b = IsPrivateEmail(boolVal)
	return nil
}

type appleName struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type appleUser struct {
	Name  appleName `json:"name"`
	Email string    `json:"email"`
}

// NewAppleProvider creates a Apple account provider.
func NewAppleProvider(ctx context.Context, ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	if ext.URL != "" {
		logrus.Warn("Apple OAuth provider has URL config set which is ignored (check GOTRUE_EXTERNAL_APPLE_URL)")
	}

	oidcProvider, err := oidc.NewProvider(ctx, DefaultAppleIssuer)
	if err != nil {
		return nil, err
	}

	provider := &AppleProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes: []string{
				"email",
				"name",
			},
			RedirectURL: ext.RedirectURI,
		},
		oidc: oidcProvider,
	}

	// If private key is configured, set JWT generator
	if ext.PrivateKey != "" {
		// Get teamID and keyID from configuration
		teamID := ext.TeamID
		keyID := ext.KeyID
		
		// If teamID or keyID is empty, log warning but continue using static secret
		if teamID == "" || keyID == "" {
			logrus.Warn("Apple OAuth: team_id or key_id not configured, JWT generation will be disabled")
		} else {
			jwtGenerator, err := NewAppleJWTGenerator(ext.PrivateKey, ext.ClientID[0], teamID, keyID)
			if err != nil {
				logrus.WithError(err).Warn("Failed to create Apple JWT generator, falling back to static secret")
			} else {
				provider.jwtGenerator = jwtGenerator
				provider.teamID = teamID
				provider.keyID = keyID
				
				// Generate initial JWT secret
				if secret, err := jwtGenerator.GenerateClientSecret(); err == nil {
					provider.currentSecret = secret
					provider.lastGenerated = time.Now()
					provider.Config.ClientSecret = secret
					logrus.Info("Apple OAuth: JWT client secret generation enabled")
				}
			}
		}
	}

	return provider, nil
}

// getOrGenerateSecret get the current client secret, if expired, regenerate it
func (p *AppleProvider) getOrGenerateSecret() string {
	p.secretMutex.RLock()
	if p.jwtGenerator != nil && p.currentSecret != "" {
		// Check if it's about to expire
		if !p.jwtGenerator.IsExpired(p.currentSecret) {
			defer p.secretMutex.RUnlock()
			return p.currentSecret
		}
	}
	p.secretMutex.RUnlock()

	// Need to regenerate
	p.secretMutex.Lock()
	defer p.secretMutex.Unlock()

	// Double check
	if p.jwtGenerator != nil && p.currentSecret != "" && !p.jwtGenerator.IsExpired(p.currentSecret) {
		return p.currentSecret
	}

	// Generate new JWT secret
	if p.jwtGenerator != nil {
		if secret, err := p.jwtGenerator.GenerateClientSecret(); err == nil {
			p.currentSecret = secret
			p.lastGenerated = time.Now()
			p.Config.ClientSecret = secret
			logrus.Debug("Generated new Apple JWT client secret")
			return secret
		} else {
			logrus.WithError(err).Error("Failed to generate Apple JWT client secret")
		}
	}

	// If JWT generation fails, return the original secret
	return p.Config.ClientSecret
}

// GetOAuthToken returns the apple provider access token
func (p AppleProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	clientSecret := p.getOrGenerateSecret()
	
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_id", p.ClientID),
		oauth2.SetAuthURLParam("secret", clientSecret),
	}
	return p.Exchange(context.Background(), code, opts...)
}

func (p AppleProvider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	authURL := p.Config.AuthCodeURL(state, opts...)
	if authURL != "" {
		if u, err := url.Parse(authURL); err != nil {
			u.RawQuery = strings.ReplaceAll(u.RawQuery, "+", "%20")
			authURL = u.String()
		}
	}
	return authURL
}

// GetUserData returns the user data fetched from the apple provider
func (p AppleProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	idToken := tok.Extra("id_token")
	if tok.AccessToken == "" || idToken == nil {
		// Apple returns user data only the first time
		return &UserProvidedData{}, nil
	}

	_, data, err := ParseIDToken(ctx, p.oidc, &oidc.Config{
		ClientID:        p.ClientID,
		SkipIssuerCheck: true,
	}, idToken.(string), ParseIDTokenOptions{
		AccessToken: tok.AccessToken,
	})
	if err != nil {
		return nil, err
	}

	return data, nil
}

// ParseUser parses the apple user's info
func (p AppleProvider) ParseUser(data string, userData *UserProvidedData) error {
	u := &appleUser{}
	err := json.Unmarshal([]byte(data), u)
	if err != nil {
		return err
	}

	userData.Metadata.Name = strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
	userData.Metadata.FullName = strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
	return nil
}
