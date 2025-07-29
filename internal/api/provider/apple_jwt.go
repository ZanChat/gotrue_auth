package provider

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// AppleJWTGenerator: Used to generate Apple OAuth JWT client secret
type AppleJWTGenerator struct {
	privateKey *ecdsa.PrivateKey
	clientID   string
	teamID     string
	keyID      string
}

// NewAppleJWTGenerator: Create a new Apple JWT generator
func NewAppleJWTGenerator(privateKeyData, clientID, teamID, keyID string) (*AppleJWTGenerator, error) {
	// Parse private key
	privateKey, err := ParseApplePrivateKey(privateKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &AppleJWTGenerator{
		privateKey: privateKey,
		clientID:   clientID,
		teamID:     teamID,
		keyID:      keyID,
	}, nil
}

// GenerateClientSecret: Generate Apple OAuth JWT client secret
func (g *AppleJWTGenerator) GenerateClientSecret() (string, error) {
	now := time.Now()
	
	claims := jwt.MapClaims{
		"iss": g.teamID,
		"iat": now.Unix(),
		"exp": now.Add(30 * 24 * time.Hour).Unix(), // Apple JWT token expires in 30 days
		"aud": "https://appleid.apple.com",
		"sub": g.clientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = g.keyID
	token.Header["alg"] = "ES256"

	signedToken, err := token.SignedString(g.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	logrus.WithField("component", "apple_jwt").Info("Generated new Apple JWT token")

	return signedToken, nil
}

// IsExpired: Check if the JWT token is about to expire (considered expired 7 days in advance)
func (g *AppleJWTGenerator) IsExpired(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &g.privateKey.PublicKey, nil
	})
	
	if err != nil {
		return true // If parsing fails, consider it expired
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			// Consider expired 7 days in advance
			return time.Now().Add(7 * 24 * time.Hour).After(expTime)
		}
	}
	
	return true
}

// ParseApplePrivateKey: Parse Apple private key (supports multiple formats)
func ParseApplePrivateKey(privateKeyData string) (*ecdsa.PrivateKey, error) {
	// Try to parse PEM format directly
	if len(privateKeyData) > 0 && privateKeyData[0] == '-' {
		block, _ := pem.Decode([]byte(privateKeyData))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}

		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS1 format
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
		}

		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not ECDSA")
		}

		return ecdsaKey, nil
	}

	// Try to parse Base64 encoded private key
	decoded, err := base64.StdEncoding.DecodeString(privateKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 private key: %w", err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		// Try PKCS1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(decoded)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ECDSA")
	}

	return ecdsaKey, nil
}