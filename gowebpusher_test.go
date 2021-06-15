package gowebpusher

import (
	"encoding/base64"
	"testing"
)

const succeed = "\u2705"
const failed = "\u274C"

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
