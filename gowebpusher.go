//Package gowebpusher helps sending push notifications to web browsers
package gowebpusher

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

//PushSubscription interface of the Push API provides a subscription's URL endpoint.
type PushSubscription struct {
	Endpoint string
	Key      PushSubscriptionKey
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
// P256dh: 🔒 Receiver public key (‘p256dh’): The p256dh key received as part of the Subscription data.
// Auth: 🔑  Auth key (‘auth’): Auth key The auth key received as part of the Subscription data.
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

	subscriptionURL, _ := url.Parse("https://fcm.googleapis.com/fcm/send/")
	claims := map[string]interface{}{
		"aud": fmt.Sprintf("%s://%s", subscriptionURL.Scheme, subscriptionURL.Host),
		"exp": time.Now().Add(time.Hour * 12).Unix(),
		"sub": "mailto:mail@mail.com"}

	for _, sub := range s.PushSubscriptions {
		res, err := s.sendNotification([]byte("{\"body\":\"Hello World\"}"), &sub, claims)
		fmt.Println(res, err)
	}

	//Testing return
	return len(s.PushSubscriptions)
}

//sendNotification will send a message/payload to a subscriber
func (s *Sender) sendNotification(payload []byte, sub *PushSubscription, claims map[string]interface{}) (*http.Response, error) {
	//VAPID keys
	VAPIDkeys := VAPIDKeys{
		s.VAPIDPublicKey, s.VAPIDPrivateKey,
	}

	// 🔒 Receiver public key [p256dh]
	buf := bytes.NewBufferString(sub.key.P256dh)
	receiverPubKey, err := base64.StdEncoding.DecodeString(buf.String())
	//receiver Public Key must have "=" padding added back before it can be decoded.
	if rem := len(receiverPubKey) % 4; rem != 0 {
		buf.WriteString(strings.Repeat("=", 4-rem))
	}
	if err != nil {
		receiverPubKey, err = base64.URLEncoding.DecodeString(buf.String())
		if err != nil {
			return nil, err
		}
	}
	// Generate shared ECDH && local Public key
	sharedECDH, localPubKey, err := generateSharedECDH(receiverPubKey)
	if err != nil {
		return nil, err
	}

	// 🔑  Auth key (‘auth’)
	// Auth key: The auth key received as part of the Subscription data.
	secretBuf := bytes.NewBufferString(sub.key.Auth)
	if rem := len(sub.key.Auth) % 4; rem != 0 {
		secretBuf.WriteString(strings.Repeat("=", 4-rem))
	}
	authKey, err := base64.StdEncoding.DecodeString(secretBuf.String())
	if err != nil {
		authKey, _ = base64.URLEncoding.DecodeString(secretBuf.String())
	}

	// Encrypt payload
	encryptionHeaderBuf, encryptedPayload, err := encryptPayload(payload, localPubKey, receiverPubKey, sharedECDH, authKey)
	if err != nil {
		return nil, err
	}

	// POST notification request
	req, err := http.NewRequest("POST", sub.Endpoint, encryptionHeaderBuf)
	if err != nil {
		return nil, err
	}

	//The TTL Header is the number of seconds the notification should stay in storage if the remote user agent isn’t actively connected.
	//“0” (Zed/Zero) means that the notification is discarded immediately if the remote user agent is not connected; this is the default.
	//This header must be specified, even if the value is “0”.
	req.Header.Set("TTL", strconv.Itoa(30))

	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Length", strconv.Itoa(len(encryptedPayload)))
	req.Header.Set("Content-Type", "application/octet-stream")

	//Generate VAPID Authorization header which contains JWT signed token and VAPID public key
	AuthorizationHeader, err := generateVAPIDAuth(VAPIDkeys, claims)
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

//generateJWTSignature ..
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

//ECDH a secure way to share public keys and generate a shared secret and local Public key
func generateSharedECDH(receiverPubKey []byte) ([]byte, []byte, error) {

	curve := elliptic.P256()
	localPrivateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Get the shared x,y point using client/receiver's Public key and local private key
	sharedX, sharedY := elliptic.Unmarshal(curve, receiverPubKey)
	if sharedX == nil {
		return nil, nil, errors.New("Invalid Public key")
	}

	sx, sy := curve.ScalarMult(sharedX, sharedY, localPrivateKey)
	if !curve.IsOnCurve(sx, sy) {
		return nil, nil, errors.New("Shared point is not on the curve")
	}

	sharedECDH := make([]byte, curve.Params().BitSize/8)
	sx.FillBytes(sharedECDH)

	return sharedECDH, elliptic.Marshal(curve, x, y), nil
}

//encryptPayload ..
func encryptPayload(message []byte, localPubKey []byte, receiverPubKey []byte, sharedECDH []byte, authKey []byte) (*bytes.Buffer, []byte, error) {

	// 🏭 Build using / derive
	prkInfoBuf := bytes.NewBuffer([]byte("WebPush: info\x00"))
	prkInfoBuf.Write(receiverPubKey)
	prkInfoBuf.Write(localPubKey)

	ikm, err := readKey(hkdf.New(sha256.New, sharedECDH, authKey, prkInfoBuf.Bytes()), 32)
	if err != nil {
		return nil, nil, err
	}

	/******* the Encryption Key and Nonce *****/
	// 	📎  salt
	// The salt needs to be 16 bytes of random data.
	salt := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, nil, err
	}

	//Content-Encoding: aes128gcm
	//🔓 = HKDF(🔑, “Content-Encoding: aes128gcm\x00” + ⚓).🏭(🙊)
	// This is the scheme described in RFC 8188. It's supported in Firefox 55+ and Chrome 60+, and replaces the older aesgcm scheme from earlier drafts. This scheme includes the salt, record size, and sender public key in a binary header block in the payload.
	encryptionKey, err := readKey(hkdf.New(sha256.New, ikm, salt, []byte("Content-Encoding: aes128gcm\x00")), 16)
	if err != nil {
		return nil, nil, err
	}

	//🎲 message nonce
	//🎲 = HKDF(🔑 , “Content-Encoding: nonce\x00” + ⚓).🏭(🙊)
	// The sender and receiver combine the PRK with a random 16-byte salt. The salt is generated by the sender, and shared with the receiver as part of the message payload.
	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonceHKDF := hkdf.New(sha256.New, ikm, salt, nonceInfo)
	encryptionNonce, err := readKey(nonceHKDF, 12)
	if err != nil {
		return nil, nil, err
	}

	// Cipher
	c, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, err
	}

	encryptionHeaderBuf := bytes.NewBuffer(salt)

	//The sender chunks the plaintext into fixed-size records, and includes this size in the message payload as the rs
	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, 4096)

	encryptionHeaderBuf.Write(rs)
	encryptionHeaderBuf.Write([]byte{byte(len(localPubKey))})
	encryptionHeaderBuf.Write(localPubKey)

	// 📄 Payload
	payloadBuf := bytes.NewBuffer(message)

	// The encrypter prefixes a “\x00\x00” to the data chunk, processes it completely, and then concatenates its encryption tag to the end of the completed chunk.
	payloadBuf.Write([]byte("\x02"))

	maxPadLen := (4096 - 16) - encryptionHeaderBuf.Len()
	payloadLen := payloadBuf.Len()
	if payloadLen > maxPadLen {
		return nil, nil, errors.New("payload has exceeded the maximum length")
	}

	padLen := maxPadLen - payloadLen

	padding := make([]byte, padLen)
	payloadBuf.Write(padding)

	// Encrypt the payload using the content encryption key (CEK)
	encryptedPayload := gcm.Seal([]byte{}, encryptionNonce, payloadBuf.Bytes(), nil)
	encryptionHeaderBuf.Write(encryptedPayload)

	return encryptionHeaderBuf, encryptedPayload, nil
}

//readKey will the key with specified length
func readKey(hkdf io.Reader, length int) ([]byte, error) {
	key := make([]byte, length)
	n, err := io.ReadFull(hkdf, key)
	if n != len(key) {
		return key, errors.New("Read length doesn't match key length")
	}
	if err != nil {
		return key, err
	}

	return key, nil
}
