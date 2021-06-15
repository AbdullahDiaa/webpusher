package gowebpusher

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
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

func TestReadKey(t *testing.T) {

}

func TestVerifyClaims(t *testing.T) {

	t.Log("Try with valid claims map, Should pass")
	{
		claims := map[string]interface{}{
			"aud": "https://fcm.googleapis.com",
			"exp": time.Now().Add(time.Hour * 12).Unix(),
			"sub": fmt.Sprintf("mailto:mail@mail.com")}

		err := verifyClaims(claims)
		if err != nil {
			t.Fatalf("\t%s\tShould be valid claim got an error instead: %s", failed, err.Error())
		}
	}

	t.Logf("\t%s\tA claim with all fields valid", succeed)

	t.Log("Expiry date should be within 24 hours")
	{
		claims := map[string]interface{}{
			"aud": "https://fcm.googleapis.com",
			"exp": time.Now().Add(time.Hour * -12).Unix(),
			"sub": fmt.Sprintf("mailto:mail@mail.com")}

		err := verifyClaims(claims)
		if err.Error() != "Expiry claim (exp) already expired" {
			t.Fatalf("\t%s\tShould return an error with the expired date got:%s", failed, err.Error())
		}
		t.Logf("\t%s\tInvalid exp claim (early)", succeed)

		//More than 24 hours
		claims["exp"] = time.Now().Add(time.Hour * 25).Unix()

		err = verifyClaims(claims)
		if err.Error() != "Expiry claim (exp) maximum value is 24 hours" {
			t.Fatalf("\t%s\tShould return an error with max value of 24 hours got:%s", failed, err.Error())
		}
		t.Logf("\t%s\tInvalid exp claim (late)", succeed)
	}

	t.Log("Subscriber claim should be an email starting with (mailto) or URL")
	{
		claims := map[string]interface{}{
			"aud": "https://fcm.googleapis.com",
			"exp": time.Now().Add(time.Hour * -12).Unix(),
			"sub": "mail@mail.com"}

		err := verifyClaims(claims)
		if err.Error() != "“Subscriber” claim (sub) is invalid, it should be an email or contact URL" {
			t.Fatalf("\t%s\tShould return an error with invalid sub got:%s", failed, err.Error())
		}
		t.Logf("\t%s\tInvalid email format for Subscriber” field", succeed)

		//non-https URL
		claims["sub"] = "http://push-service.com"

		err = verifyClaims(claims)
		if err.Error() != "“Subscriber” claim (sub) is invalid, it should be an email or contact URL" {
			t.Fatalf("\t%s\tShould return an error with invalid sub got:%s", failed, err.Error())
		}
		t.Logf("\t%s\tInvalid URL (non-https) format for Subscriber” field", succeed)
	}

}
