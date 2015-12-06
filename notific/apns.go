package notific

import (
	"github.com/anachronistic/apns"
	"log"
)

// NO RETURN, expected to be run as a gofunc.
// Generate an APNS message and send it to apple!
func SendIOSNotification(endpoint *Endpoint, notification *Notification) {
	log.Println("Sending a message to APNS for endpoint ", endpoint.Id)

	message, err := decodeMessage(notification.Payload)

	if err != nil {
		log.Println("Failed to decode notification message: ", err)
		UpdateNotification(notification, ERROR)
		return
	}

	payload := apns.NewPayload()
	payload.Alert = message
	payload.Badge = 1
	payload.Sound = "bingbong.aiff"

	pn := apns.NewPushNotification()
	pn.DeviceToken = endpoint.DeviceToken
	pn.AddPayload(payload)

	log.Println("Sending to APNS Host: ", *apnsHost)

	client := apns.NewClient(*apnsHost, *apnsCert, *apnsKey)

	resp := client.Send(pn)
	alert, _ := pn.PayloadString()

	status := REJECTED

	if resp.Success {
		log.Println(notification.Id, " send OK.")
		status = SENT
	} else {
		log.Println(notification.Id, " failed: ", alert, ", ", resp.Error)
		status = ERROR
	}

	UpdateNotification(notification, status)
}
