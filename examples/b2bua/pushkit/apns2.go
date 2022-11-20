package pushkit

import (
	"encoding/json"
	"log"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
)

func DoPushKit2(p12Cert string, deviceToken string, payload map[string]string) {
	authKey, err := token.AuthKeyFromFile("./AuthKey_D9N2S55R83.p8")
	if err != nil {
		log.Fatal("token error:", err)
	}

	t := &token.Token{
		AuthKey: authKey,
		// KeyID from developer account (Certificates, Identifiers & Profiles -> Keys)
		KeyID: "D9N2S55R83",
		// TeamID from developer account (View Account -> Membership)
		TeamID: "5J859T6AE8",
	}

	client := apns2.NewTokenClient(t)
	data, _ := json.Marshal(payload)
	notification := &apns2.Notification{
		DeviceToken: deviceToken,
		Topic:       "com.paycall.mtravel2.voip",
		Payload:     data,
	}
	notification.PushType = apns2.PushTypeVOIP
	res, err := client.Push(notification)

	if err != nil {
		log.Fatal("push error:", err)
	}
	log.Printf("%v %v %v", res.StatusCode, res.ApnsID, res.Reason)
}
