package pushkit

import (
	"encoding/json"
	"log"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
)

func DoPushKit2(p8Cert string, deviceToken string, payload map[string]string) {
	authKey, err := token.AuthKeyFromFile(p8Cert)
	if err != nil {
		log.Fatal("token error:", err)
	}

	t := &token.Token{
		AuthKey: authKey,
		// KeyID from developer account (Certificates, Identifiers & Profiles -> Keys)
		KeyID: "2RTKYJH728",
		// TeamID from developer account (View Account -> Membership)
		TeamID: "954G8NSFLG",
	}

	client := apns2.NewTokenClient(t)
	data, _ := json.Marshal(payload)
	notification := &apns2.Notification{
		DeviceToken: deviceToken,
		Topic:       "com.paycall.mtravel.voip",
		Payload:     data,
	}
	notification.PushType = apns2.PushTypeVOIP
	res, err := client.Push(notification)

	if err != nil {
		log.Fatal("push error:", err)
	}
	log.Printf("%v %v %v", res.StatusCode, res.ApnsID, res.Reason)
}
