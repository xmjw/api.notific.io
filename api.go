package main

import (
	"code.google.com/p/go-uuid/uuid"
	"database/sql"
	"encoding/base64"
	gojson "encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/anachronistic/apns"
	"github.com/bitly/go-simplejson"
	//	"github.com/xmjw/api.notific.io/notific"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Each notifcation that we send.
type Notification struct {
	Id         string
	EndpointId string
	Payload    string
	Status     string
	Enc        bool
	CreatedAt  time.Time
}

// The Endpoint (which later can be grouped on users etc)
type Endpoint struct {
	Id          string
	Token       string
	DeviceId    string
	CreatedAt   time.Time
	DeviceType  string
	DeviceToken string
}

const QUEUED string = "QUEUED"
const SENT string = "SENT"
const ERROR string = "ERROR"
const REJECTED string = "REJECTED"

// Get our connection string and handle any issues.
// Let database/sql handle the pooling for us. Just be careful
// to write code that doesn't do locking.
func DbConnection() *sql.DB {
	db, err := sql.Open("postgres", *dbConStr)
	if err != nil {
		log.Fatal("Failed to open database connection. The server will shut down: %v", err)
	}
	return db
}

// Try and find the API entry in the DB. Then cache as necessary.Ffunc FindEndpoint(id string) (*Endpoint, error) {
func findEndpoint(id string) (*Endpoint, error) {
	conn := DbConnection()
	rows := conn.QueryRow("SELECT id, token, device_id, device_type, device_token, created_at FROM endpoints where id = $1", id)
	ep := Endpoint{}

	if rows == nil {
		return nil, errors.New("Failed to query for endpoint. Cannot continue.")
	}

	err := rows.Scan(&ep.Id, &ep.Token, &ep.DeviceId, &ep.DeviceType, &ep.DeviceToken, &ep.CreatedAt)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to parse endpoint details into a struct: %v ", err))
	}

	// PG can mysteriously load ' IOS      ' despite 'IOS' being in the DB. Fix properly later, something else
	// fishy is probably happening.
	ep.DeviceType = strings.TrimSpace(ep.DeviceType)

	return &ep, nil
}

// load a notification from the database. Hopefully.
func findNotification(id string) (*Notification, error) {
	conn := DbConnection()
	rows := conn.QueryRow("SELECT id, endpoint_id, payload, status, encrypted, created_at FROM notifications where id = $1", id)
	notif := Notification{}

	if rows == nil {
		return nil, errors.New("Failed to query for notification. Cannot continue.")
	}

	err := rows.Scan(&notif.Id, &notif.EndpointId, &notif.Payload, &notif.Status, &notif.Enc, &notif.CreatedAt)

	if err != nil {
		log.Println("Failed to load a notification: ", err)
		return nil, errors.New(fmt.Sprintf("Failed to parse endpoint details into a struct: %v ", err))
	}

	notif.Status = strings.TrimSpace(notif.Status)

	return &notif, nil
}

func findNotificationsForEndpoint(endpoint *Endpoint, offset int, limit int) (*[]Notification, error) {
	conn := DbConnection()
	rows, err := conn.Query("SELECT id, endpoint_id, payload, status, encrypted, created_at FROM notifications where endpoint_id = $1 ORDER BY created_at LIMIT $2 OFFSET $3",
		endpoint.Id,
		limit,
		offset)

	if err != nil {
		log.Println("Failed querying for notifications: ", err)
		return nil, errors.New("Failed to query for notification. Cannot continue.")
	}

	// We're expecting users to behave in a 'few unread messages' way, so optimise for small numbers by default
	notifications := make([]Notification, limit, limit)
	log.Println("Notification array is", len(notifications), "segments long (", limit, ").")

	if rows == nil {
		log.Println("Failed querying for notifications, no error but `rows` was nil. :-(")
		return nil, errors.New("Failed to query for notification. Cannot continue.")
	}

	i := 0
	defer rows.Close()
	for rows.Next() {
		notif := Notification{}
		err := rows.Scan(&notif.Id, &notif.EndpointId, &notif.Payload, &notif.Status, &notif.Enc, &notif.CreatedAt)

		if err != nil {
			log.Println("Attempting to load one of the notifications errored: ", err)
			return nil, err
		} else if notif.Id != "" {
			notif.Status = strings.TrimSpace(notif.Status)
			notifications[i] = notif
			i++
		}
	}

	if err != nil {
		log.Println("Failed to load a notification: ", err)
		return nil, errors.New(fmt.Sprintf("Failed to parse endpoint details into a struct: %v ", err))
	}

	notifications = notifications[:i]

	return &notifications, nil
}

func updateNotification(notification *Notification, status string) {
	c := DbConnection()
	_, err := c.Exec(
		"UPDATE notifications SET status = $1 WHERE id = $2",
		status,
		notification.Id)

	if err != nil {
		log.Println("Error while trying to update a Notification record (", notification.Id, "): ", err)
	}

	log.Println("Notification (", notification.Id, ") has been updated with status: ", status)
}

// Checks that the device type is either
func checkDeviceType(t string) bool {
	if t == "IOS" || t == "ANDROID" || t == "WINDOWS" {
		return true
	} else {
		return false
	}
}

// Checks a typical token 8 x alphachar
func checkToken(val string) bool {
	log.Println("Testing Token: ", val)
	exp := "^[a-zA-Z0-9]{8}$"
	return checkRegExp(val, exp)
}

func checkIOSToken(val string) bool {
	log.Println("Testing UUID: ", val)
	exp := "^[a-zA-Z0-9]{64}$"
	return checkRegExp(val, exp)
}

// Tests for a version 4 UUID
func checkUuid(val string) bool {
	log.Println("Testing UUID: ", val)
	exp := "^[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}$"
	return checkRegExp(val, exp)
}

// Check a string against a regex
func checkRegExp(val string, exp string) bool {
	match, err := regexp.MatchString(exp, val)
	if err != nil {
		log.Println("Matching RegExp raised an error.")
		return false
	}
	return match
}

// 'charabet' an alphabet with all meaningful glyphs, i.e., numbers and letters.
const charabet = "023456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnopqrstuvwxyz"

// Generates 8 x alphachar string as a unique ID.
func createId() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var bytes = make([]byte, 8)
	for k, _ := range bytes {
		bytes[k] = charabet[r.Intn(len(charabet))]
	}
	return string(bytes)
}

// create the id's we are going to use for messages.
func createUuid() string {
	return uuid.New()
}

// Stores a notification in the database. We base 64 encode the message, not for security, but
// to help protect against SQL injection. This way we are so restrictive on the outside data that
// we store, it should be virtually impossible to perform a SQL injection attack.
func createNotification(endpoint *Endpoint, message string, encrypted bool) (*Notification, error) {
	message64 := encodeMessage(message)
	c := DbConnection()

	id := createUuid()

	log.Println("EndpontId: ", endpoint.Id)

	_, err := c.Exec(
		"INSERT INTO notifications (id, endpoint_id, payload, status, encrypted, created_at) VALUES ($1,$2,$3,$4,$5,NOW())",
		id,
		endpoint.Id,
		message64,
		QUEUED,
		encrypted)

	if err != nil {
		log.Println("Error while trying to create a Notification record: ", err)
		return nil, errors.New("Failed to generate a notification for this message.")
	}

	return findNotification(id)
}

// Creates a new registration...
func createEndpoint(deviceType string, deviceId string, deviceToken string) (*Endpoint, error) {
	if !checkUuid(deviceId) {
		return nil, errors.New("Invalid Device ID.")
	}

	if !checkDeviceType(deviceType) {
		return nil, errors.New("Invalid Device type.")
	}

	// Enforce IOS device type at the moment, as no other companion app is available.
	if !checkIOSToken(deviceToken) {
		return nil, errors.New("Invalid Device Token (IOS)")
	}

	// Create our own internal values. These are supposed to memorable (ish) so they're shorter than UUIDs.
	endpointId := createId()
	endpointToken := createId()

	c := DbConnection()

	_, err := c.Exec(
		"INSERT INTO endpoints (id, token, device_id, device_type, device_token, created_at) VALUES ($1,$2,$3,$4,$5,NOW())",
		endpointId,
		endpointToken,
		deviceId,
		deviceType,
		deviceToken)

	if err != nil {
		log.Println("Error while trying to inset endpoint: ", err)
		return &Endpoint{}, err
	}

	return &Endpoint{Id: endpointId,
		Token:       endpointToken,
		DeviceId:    deviceId,
		DeviceType:  deviceType,
		DeviceToken: deviceToken}, nil
}

// Simply base64 encode the messages, to avoid any SLQ injection issues.
func encodeMessage(message string) string {
	data := []byte(message)
	return base64.StdEncoding.EncodeToString(data)
}

// Reverse base64 encoding.
func decodeMessage(message string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		log.Println("error:", err)
		return "", err
	}
	return string(data[:]), nil
}

// Enhanced security, this is the user we think it is, using the app we think
// they're using. So we let them see old notifications, and allow recycling etc.
func authenticateRequest(device string, token string, endpoint *Endpoint) bool {
	return device == endpoint.DeviceId && validateRequest(token, endpoint)
}

// This checks the user's API token against that in the DB.
// It means that we can trigger the endpoint. NOT that we can do anything else.
// For administration of this endpoint, see AuthenticateRequest().
func validateRequest(token string, endpoint *Endpoint) bool {
	return endpoint.Token == token
}

// Store the request in the DB, and send to APNS
func RecordNotification(user Endpoint, payload string) bool {
	return false
}

// NO RETURN, expected to be run as a gofunc.
// Generate an APNS message and send it to apple!
func SendIOSNotification(endpoint *Endpoint, notification *Notification) {
	log.Println("Sending a message to APNS for endpoint ", endpoint.Id)

	message, err := decodeMessage(notification.Payload)

	if err != nil {
		log.Println("Failed to decode notification message: ", err)
		updateNotification(notification, ERROR)
		return
	}

	payload := apns.NewPayload()
	payload.Alert = message
	payload.Badge = 1
	payload.Sound = "bingbong.aiff"

	pn := apns.NewPushNotification()
	pn.DeviceToken = endpoint.DeviceToken
	pn.AddPayload(payload)

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

	updateNotification(notification, status)
}

// Check the status of a notification, without any valudation keys etc, but
// the only data returned is the delivery state.
func CheckNotification(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request to confirm a notification")

	vars := mux.Vars(r)
	id := vars["id"]
	fof := fmt.Sprintf("{\"error\":\"Invalid notification.\",\"details\":\"Could not find requested notification.\"}")

	if !checkUuid(id) {
		log.Println("Invalid notification ID: ", id)
		http.Error(w, fof, 401)
		return
	}

	notif, err := findNotification(id)

	if err != nil {
		log.Println("Notification (", id, ") could not be found: ", err)
		http.Error(w, fof, 404)
		return
	}

	// 201 and return the notifcation ID so it can be queried later
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "{ \"status\": \"%v\" }", notif.Status)
}

// Http handler for creates...
func CreateTrigger(w http.ResponseWriter, r *http.Request) {
	log.Println("Received a POST against an ID. Working.")

	vars := mux.Vars(r)
	id := vars["id"]

	// We use the same error every time, as this makes it harder to try and hack from the outside with
	// brute force attempt to get the message. Timing attacks are still an issue however.
	fof := fmt.Sprintf("{\"error\":\"Invalid endpoint/token.\",\"details\":\"Could not find requested endpoint.\"}")

	if !checkToken(id) {
		log.Println("Invalid endpoint: ", id)
		http.Error(w, fof, 401)
		return
	}

	endpoint, err := findEndpoint(id)

	if err != nil {
		log.Println("Problem finding endpoint in database: ", err)
		http.Error(w, fof, 401)
		return
	}

	// Load the JSON.
	payload, err := simplejson.NewFromReader(r.Body)

	if err != nil {
		log.Println("Failed to parse request JSON: ")
		http.Error(w, fmt.Sprintf("{\"error\":\"Request body invalid.\",\"details\":\"%v\"}", err), 400)
		return
	}

	token := payload.Get("token").MustString()
	message := payload.Get("message").MustString()
	action := payload.Get("action").MustString()

	if !checkToken(token) {
		log.Println("Invalid token: ", token)
		http.Error(w, fof, 401)
		return
	}

	if validateRequest(token, endpoint) == false {
		log.Println("Token was not valid against the endpoint: ", token)
		http.Error(w, fof, 401)
	}

	// Now check against the JSON
	log.Println("Valid alert: ", token, message, action)

	if token != endpoint.Token {
		log.Println("Endpoint token did not match DB stored token: ", token, vars["token"])
		http.Error(w, fof, 404)
		return
	}

	notif, err := createNotification(endpoint, message, false)

	if err != nil {
		log.Println("Failed to create notification: ", err)
		http.Error(w, fmt.Sprintf("{\"error\":\"Creating the notification failed.\",\"details\":\"%v\"}", err), 400)
		return
	}

	// Identify the service we'll use to deliver the message
	if endpoint.DeviceType == "IOS" {
		// This should be a GO Func.
		go func(endpoint *Endpoint, notif *Notification) {
			log.Println("Sending Notification to Apple: ", notif.Id)
			SendIOSNotification(endpoint, notif)
		}(endpoint, notif)
		// } else if endpoint.DeviceType == "ANDROID" {
		// 	serviceId = "Not implemented!"
		// } else if endpoint.DeviceType == "WINDOWS" {
		// 	serviceId = "Not implemented!"
	} else {
		log.Println("Failed to find a device service match: '", endpoint.DeviceType, "'")
		http.Error(w, "{\"error\":\"Could not identify device type.\",\"details\":\"Device type did not match a configured type.\"}", 400)
		return
	}

	// 201 and return the notifcation ID so it can be queried later
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "{ \"status\":\"%v\" \"id\": \"%v.\" }", notif.Status, notif.Id)
}

// Http handler for creates...
func NotificationsForEndpoint(w http.ResponseWriter, r *http.Request) {
	log.Println("Received a GET. Listing notifications...")

	vars := mux.Vars(r)
	id := vars["id"]
	token := r.Header.Get("token")

	offsetStr := r.FormValue("offset")

	offset := 0
	limit := 5

	if offsetStr != "" {
		offsetInt, err := strconv.ParseInt(offsetStr, 10, 32)
		if err != nil {
			log.Println("Could not convert the offset (", offsetStr, ") to an integer. ", err)
			http.Error(w, fmt.Sprintf("{\"error\":\"Invalid Offset\",\"details\":\"%v\"}", err), 400)
			return
		}
		offset = int(offsetInt)
	}

	log.Println("Using offset:", offset, " (via ", offsetStr, ")")

	fof := fmt.Sprintf("{\"error\":\"Invalid endpoint/token.\",\"details\":\"Could not find requested endpoint.\"}")

	if !checkToken(id) {
		log.Println("Invalid ID: ", id)
		http.Error(w, fof, 401)
		return
	}

	if !checkToken(token) {
		log.Println("Invalid token: ", token)
		http.Error(w, fof, 401)
		return
	}

	endpoint, err := findEndpoint(id)

	if err != nil {
		log.Println("Failed to find endpoint: ", id)
		http.Error(w, fof, 404)
	}

	if validateRequest(token, endpoint) == false {
		log.Println("Token was not valid against the endpoint: ", token)
		http.Error(w, fof, 401)
	}

	notifications, err := findNotificationsForEndpoint(endpoint, offset, limit)

	if err != nil {
		log.Println("Failed to find notifications: ", id)
		http.Error(w, fof, 404)
	}

	log.Println(len(*notifications), "notifications were found! Yahoo.")

	// render notifications in JSON, needs something more substantial than previous.
	jsonByte, err := gojson.Marshal(notifications)
	if err != nil {
		log.Println("Failed to render JSON: ", err)
		http.Error(w, fof, 400)
	}

	// really need the JSON object, so we can loop through and decode the payload.
	// this is totall pointless... must be a faster way...
	jsonObj, err := simplejson.NewJson(jsonByte)

	if err != nil {
		log.Println("Failed to do elastics on JSON: ", err)
		http.Error(w, fof, 400)
	}

	for i, _ := range jsonObj.MustArray() {
		payload := jsonObj.GetIndex(i).Get("Payload").MustString()
		message, err := decodeMessage(payload)

		if err != nil {
			log.Println("Failed to do elastics on JSON: ", err)
			http.Error(w, fof, 400)
		}

		jsonObj.GetIndex(i).Del("Payload")
		jsonObj.GetIndex(i).Set("message", message)
	}

	newJsonByte, err := jsonObj.MarshalJSON()

	if err != nil {
		log.Println("Failed to do elastics on JSON: ", err)
		http.Error(w, fof, 400)
	}

	fmt.Fprintln(w, string(newJsonByte))
}

// Http handler for creates...
func DeleteTrigger(w http.ResponseWriter, r *http.Request) {
	log.Println("Received a DELETE. Working. ")
}

// If a user has miraculously started getting spam on this endpoint,
// this allows them to simply reset their tokens, and stop it.
// Like the read requests, this route requires the device ID, or anyone
// could reset your token. Which is obviously bad.
func RecycleToken(w http.ResponseWriter, r *http.Request) {
	log.Println("Received a PATCH. Will recycle token if request is valid.")

}

// When a new mobile app is registering itself, we use this.
func RegisterDevice(w http.ResponseWriter, r *http.Request) {
	log.Println("Received a POST. Registering a new Device!")

	data, err := simplejson.NewFromReader(r.Body)

	if err != nil {
		log.Println("Failed to parse incoming JSON: ", err)
		http.Error(w, fmt.Sprintf("{\"error\":\"JSON Parse Failure\",\"details\":\"%v\"}", err), 500)
		return
	}

	device_type := data.Get("deviceType").MustString()
	device_id := data.Get("deviceId").MustString()
	device_token := data.Get("deviceToken").MustString()

	log.Print("A new device registration will be created for an '", device_type, "'.")

	endpoint, err := createEndpoint(device_type, device_id, device_token)

	if err != nil {
		log.Println("Failed to create a new endpoint: ", err)
		http.Error(w, fmt.Sprintf("{\"error\":\"Failed to create a new endpoint.\",\"details\":\"%v\"}", err), 500)
		return
	}

	// Off in the background we'll report a new user using this software.
	// How's that for dogfood?
	go func(device_type string) {
    if *notificEndpoint != "" {
			log.Println("Using Notific.io to report new registration: ", device_type)
			_, err := http.Post(fmt.Sprintf("http://api.io/"),
				"application/json",
				nil)

			if err != nil {
				log.Println("Failed to notify with io about a new user.")
			}
		} else {
			log.Println("No inbuilt notific token to dogfood a regisrtation with...")			
		}
	}(device_type)

	// 201 OK (but a little bit more)
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "{ \"endpoint\":\"%v\", \"token\": \"%v\" }", endpoint.Id, endpoint.Token)
}

// Core Web stuff for routing.
func webServer() {
	log.Println("Building routes to listen on: ", *httpPort)
	r := mux.NewRouter()
	r.HandleFunc("/notification/{id}", CheckNotification).Methods("GET")
	r.HandleFunc("/{id}", CreateTrigger).Methods("POST")
	r.HandleFunc("/{id}", NotificationsForEndpoint).Methods("GET")
	r.HandleFunc("/{id}", DeleteTrigger).Methods("DELETE")
	r.HandleFunc("/{id}/recycle", RecycleToken).Methods("PATCH")
	r.HandleFunc("/", RegisterDevice).Methods("POST")
	http.Handle("/", r)
	http.ListenAndServe(fmt.Sprintf(":%v", *httpPort), nil)
}

var (
	dbConStr        *string = flag.String("database", "", "Postgres Database Connection String")
	httpPort        *string = flag.String("port", "5000", "HTTP Port to listen on, defaults to 5000")
	notificToken    *string = flag.String("token", "", "Notific.io token")
	notificEndpoint *string = flag.String("endpoint", "", "Notific.io endpoint ID")
	apnsHost        *string = flag.String("apns", "gateway.sandbox.push.apple.com:2195", "Apple APNS Host")
	apnsCert        *string = flag.String("cert", "", "Apple APNS Certificate")
	apnsKey         *string = flag.String("pem", "", "Apple PEM Key")
)

// Entry point.
func main() {
	flag.Parse()
	log.Println("Starting up api.io")
	webServer()
}
