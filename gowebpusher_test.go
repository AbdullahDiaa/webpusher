package gowebpusher

import (
	"encoding/base64"
	"testing"
)

const succeed = "\u2705"
const failed = "\u274C"

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
		t.Fatalf("\t%s\t%s != %s", failed, a, b)
	}
}

//TestKeys will test validity and VAPID keys generation
func TestKeys(t *testing.T) {
	t.Log("Make sure correct Public and Private VAPID keys are generated")
	{
		privKey, pubKey, err := GenerateVAPID()
		if err != nil {
			t.Fatalf("\t%s\tShould generate VAPID keys, got an error %s", failed, err.Error())
		}
		t.Logf("\t%s\tPublic key and Private key generated successfully", succeed)

		//Validate keys length
		if len(pubKey) != 87 {
			t.Fatalf("\t%s\tInvalid Public VAPID key", failed)
		}
		t.Logf("\t%s\tPrivate key length is valid", succeed)

		if len(privKey) != 43 {
			t.Fatalf("\t%s\tInvalid Private VAPID key", failed)
		}
		t.Logf("\t%s\tPublic key length is valid", succeed)

		_, err = base64.RawURLEncoding.DecodeString(privKey)
		if err != nil {
			t.Fatalf("\t%s\tInvalid Private key: %s", failed, err.Error())
		}
		t.Logf("\t%s\tPrivate key is valid", succeed)

		_, err = base64.RawURLEncoding.DecodeString(pubKey)
		if err != nil {
			t.Fatalf("\t%s\tInvalid Public key: %s", failed, err.Error())
		}
		t.Logf("\t%s\tPublic key is valid", succeed)
	}
}
