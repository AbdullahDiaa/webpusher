//Package gowebpusher helps sending push notifications to web browsers
package gowebpusher

//Sender instance
type Sender struct {
	PushSubscriptions []PushSubscription
}

//PushSubscription interface of the Push API provides a subscription's URL endpoint.
type PushSubscription struct {
	Endpoint       string
	SubscriptionID string
	key            PushSubscriptionKey
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
	s.PushSubscriptions = make([]PushSubscription, 0, 1000)
}

//Send will deliver the notification to all subscriptions
func (s *Sender) Send() int {
	//Testing return
	return len(s.PushSubscriptions)
}
