//Package gowebpusher helps sending push notifications to web browsers
package gowebpusher

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//PushSubscription interface of the Push API provides a subscription's URL endpoint.
type PushSubscription struct {
	Endpoint string
	key      PushSubscriptionKey
}

//Sender instance
type Sender struct {
	PushSubscriptions []PushSubscription
	VAPIDPublicKey    string
	VAPIDPrivateKey   string
}

//VAPIDKeys contains the public and private VAPID keys
type VAPIDKeys struct {
	Public  string
	Private string
}

//PushSubscriptionKey represents a client public key, which can then be sent to a server and used in encrypting push message data.
// P256dh: An Elliptic curve Diffie–Hellman public key on the P-256 curve (that is, the NIST secp256r1 elliptic curve).  The resulting key is an uncompressed point in ANSI X9.62 format.
// Auth: An authentication secret, as described in Message Encryption for Web Push.
type PushSubscriptionKey struct {
	P256dh string
	Auth   string
}

//NewSender will initialize an instance of sender
func NewSender() *Sender {
	s := &Sender{}
	s.Initialize()
	return s
}

//Initialize will set the default values of the sender instance
func (s *Sender) Initialize() {
	//s.PushSubscriptions = make([]PushSubscription, 0, 1000)
}

//Send will deliver the notification to all subscriptions
func (s *Sender) Send() int {
	for _, sub := range s.PushSubscriptions {
		res, err := s.sendNotification([]byte("Hey 3"), &sub)
		fmt.Println(res, err)
	}
	//Testing return
	return len(s.PushSubscriptions)
}

func (s *Sender) sendNotification(message []byte, sub *PushSubscription) (*http.Response, error) {
	//VAPID keys
	VAPIDkeys := VAPIDKeys{
		s.VAPIDPublicKey, s.VAPIDPrivateKey,
	}

	payloadBuf := bytes.NewBuffer([]byte(""))

	// POST request
	req, err := http.NewRequest("POST", sub.Endpoint, payloadBuf)
	if err != nil {
		return nil, err
	}

	//Generate VAPID Authorization header which contains JWT signed token and VAPID public key
	subscriptionURL, _ := url.Parse(sub.Endpoint)
	claims := map[string]interface{}{
		"aud": fmt.Sprintf("%s://%s", subscriptionURL.Scheme, subscriptionURL.Host),
		"exp": time.Now().Add(time.Hour * 12).Unix(),
		"sub": "mailto:mail@mail.com"}

	AuthorizationHeader, err := GenerateVAPIDAuth(VAPIDkeys, claims)
	if err != nil {
		return nil, err
	}
	// Set VAPID authorization header
	req.Header.Set("Authorization", AuthorizationHeader)

	tr := &http.Transport{
		IdleConnTimeout: 30 * time.Second,
	}
	client := &http.Client{Transport: tr}
	return client.Do(req)
}

//GenerateVAPID will generate public and private VAPID keys using ECDH protocl
func GenerateVAPID() (vapidPrivateKey string, vapidPublicKey string, err error) {
	curve := elliptic.P256()

	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", "", err
	}

	publicKey := elliptic.Marshal(curve, x, y)

	privKey := base64.RawURLEncoding.EncodeToString(privateKey)
	pubKey := base64.RawURLEncoding.EncodeToString(publicKey)
	return privKey, pubKey, nil
}

// validateVAPIDKeys will validate the length and encoding of VAPID keys
func validateVAPIDKeys(keys VAPIDKeys) error {
	if len(keys.Public) != 87 {
		return errors.New("Invalid Public key length")
	}

	if len(keys.Private) != 43 {
		return errors.New("Invalid Private key length")
	}

	_, err := base64.RawURLEncoding.DecodeString(keys.Private)
	if err != nil {
		return errors.New("Invalid Private key")
	}

	_, err = base64.RawURLEncoding.DecodeString(keys.Public)
	if err != nil {
		return errors.New("Invalid Public key")
	}
	return nil
}

//verifyClaims will verify the claims of JWT string
func verifyClaims(claims map[string]interface{}) error {
	//Validate claims
	// sub: The “Subscriber” a mailto link for the administrative contact for this feed.
	// It’s best if this email is not a personal email address,
	// but rather a group email so that if a person leaves an organization,
	// is unavailable for an extended period, or otherwise can’t respond, someone else on the list can.
	if _, ok := claims["sub"]; ok {
		if !(strings.HasPrefix(claims["sub"].(string), "mailto:")) && !(strings.HasPrefix(claims["sub"].(string), "https://")) {
			return errors.New("“Subscriber” claim (sub) is invalid, it should be an email or contact URL")
		}
	}

	//exp : “Expires” this is an integer that is the date and time that this VAPID header should remain valid until.
	// It doesn’t reflect how long your VAPID signature key should be valid, just this specific update.
	// It can be no more than 24 hours
	if _, ok := claims["exp"]; ok {
		now := time.Now().Unix()
		tomorrow := time.Now().Add(24 * time.Hour).Unix()
		if now > claims["exp"].(int64) {
			return errors.New("Expiry claim (exp) already expired")
		}
		if claims["exp"].(int64) > tomorrow {
			return errors.New("Expiry claim (exp) maximum value is 24 hours")
		}
	}
	return nil
}

//GenerateVAPIDAuth will generate Authorization header for web push notifications
func generateVAPIDAuth(keys VAPIDKeys, claims map[string]interface{}) (string, error) {

	//Validate VAPID Keys
	if err := validateVAPIDKeys(keys); err != nil {
		return "", err
	}

	//Verify Claims
	if err := verifyClaims(claims); err != nil {
		return "", err
	}

	// JWTInfo is base64 Encoded {"typ":"JWT","alg":"ES256"} which is the first part of the JWT Token
	JWTInfo := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9."

	// JWTData is the second part of the token which contains all the claims encoded in base64
	jsonValue, err := json.Marshal(claims)
	if err != nil {
		return "", errors.New("Marshaling Claims JSON failed" + err.Error())
	}
	JWTData := strings.TrimRight(base64.URLEncoding.EncodeToString(jsonValue), "=")

	JWTSignature, err := generateJWTSignature(keys, JWTInfo+JWTData)
	if err != nil {
		return "", err
	}

	//Compose the JWT Token string
	JWTString := JWTInfo + JWTData + JWTSignature

	// Construct the VAPID header
	VAPIDAuth := fmt.Sprintf(
		"vapid t=%s, k=%s",
		JWTString,
		keys.Public,
	)

	return VAPIDAuth, nil
}

func generateJWTSignature(keys VAPIDKeys, JWTInfoAndData string) (string, error) {
	// Signature is the third part of the token, which includes the data above signed with the private key
	// Preparing ecdsa.PrivateKey for signing
	privKeyDecoded, err := base64.RawURLEncoding.DecodeString(keys.Private)
	if err != nil {
		return "", errors.New("Invalid VAPID private key string, cannot decode it")
	}

	curve := elliptic.P256()
	px, py := curve.ScalarMult(
		curve.Params().Gx,
		curve.Params().Gy,
		privKeyDecoded,
	)

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     px,
		Y:     py,
	}

	// Private key
	d := &big.Int{}
	d.SetBytes(privKeyDecoded)

	privKey := &ecdsa.PrivateKey{
		PublicKey: pubKey,
		D:         d,
	}

	// Get the key
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write([]byte(JWTInfoAndData))

	// Sign JWTInfo and JWTData using the private key
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hasher.Sum(nil))
	if err != nil {
		return "", errors.New("Err singing data")
	}

	curveBits := privKey.Curve.Params().BitSize

	if curveBits != 256 {
		return "", errors.New("curveBits should be 256")
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return "." + strings.TrimRight(base64.URLEncoding.EncodeToString(out), "="), nil
}

//GenerateVAPIDAuth will generate Authorization header for web push notifications
func GenerateVAPIDAuth(keys VAPIDKeys, claims map[string]interface{}) (string, error) {

	//Validate VAPID Keys
	if err := validateVAPIDKeys(keys); err != nil {
		return "", err
	}

	//Verify Claims
	if err := verifyClaims(claims); err != nil {
		return "", err
	}

	// JWTInfo is base64 Encoded {"typ":"JWT","alg":"ES256"} which is the first part of the JWT Token
	JWTInfo := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9."

	// JWTData is the second part of the token which contains all the claims encoded in base64
	jsonValue, err := json.Marshal(claims)
	if err != nil {
		return "", errors.New("Marshaling Claims JSON failed" + err.Error())
	}
	JWTData := strings.TrimRight(base64.URLEncoding.EncodeToString(jsonValue), "=")

	JWTSignature, err := generateJWTSignature(keys, JWTInfo+JWTData)
	if err != nil {
		return "", err
	}

	//Compose the JWT Token string
	JWTString := JWTInfo + JWTData + JWTSignature

	// Construct the VAPID header
	VAPIDAuth := fmt.Sprintf(
		"vapid t=%s, k=%s",
		JWTString,
		keys.Public,
	)

	return VAPIDAuth, nil
}
