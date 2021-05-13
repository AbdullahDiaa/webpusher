package gowebpusher

import "testing"

func TestSend(t *testing.T) {
	//Create sender instance
	s := NewSender()
	PushSubscriptions := []PushSubscription{
		{
			Endpoint:       "ENDPOINT",
			SubscriptionID: "ID",
			key: PushSubscriptionKey{
				P256dh: "P256dh",
				Auth:   "AUTH KEY",
			},
		},
	}
	s.PushSubscriptions = PushSubscriptions
	res := s.Send()
	assertEqual(t, res, 1)
}

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Fatalf("%s != %s", a, b)
	}
}
