package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"github.com/anachronistic/apns"
	"github.com/bitly/go-simplejson"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// The Endpoint (which later can be grouped on users etc)
type Endpoint struct {
	Id          string
	Token       string
	DeviceId    string
	CreatedAt   time.Time
	DeviceType  string
	DeviceToken string
}

// Each notifcation that we send.
type Notification struct {
	Id        string
	UserId    string
	Payload   string
	Status    string
	CreatedAt time.Time
}

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
	rows := conn.QueryRow("SELECT token, device_id, device_type, device_token, created_at FROM endpoints where id = $1", id)
	ep := Endpoint{}

	if rows == nil {
		return nil, errors.New("Failed to query for endpoint. Cannot continue.")
	}

	err := rows.Scan(&ep.Token, &ep.DeviceId, &ep.DeviceType, &ep.DeviceToken, &ep.CreatedAt)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to parse endpoint details into a struct: %v ", err))
	}

	// PG can mysteriously load ' IOS      ' despite 'IOS' being in the DB. Fix properly later, something else
	// fishy is probably happening.
	ep.DeviceType = strings.TrimSpace(ep.DeviceType)

	return &ep, nil
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
func checkUUID(val string) bool {
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
const charabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Generates 8 x alphachar string as a unique ID.
func createId() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var bytes = make([]byte, 8)
	for k, _ := range bytes {
		bytes[k] = charabet[r.Intn(len(charabet))]
	}
	return string(bytes)
}

// Creates a new registration...
func createEndpoint(deviceType string, deviceId string, deviceToken string) (*Endpoint, error) {
	if !checkUUID(deviceId) {
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

	row, err := c.Exec(
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

	fmt.Println(row)

	return &Endpoint{Id: endpointId,
		Token:       endpointToken,
		DeviceId:    deviceId,
		DeviceType:  deviceType,
		DeviceToken: deviceToken}, nil
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

// Generate an APNS message and send it to apple!
func SendNotification(endpoint *Endpoint, message string) {
	log.Println("Sending a message to APNS for endpoint ", endpoint.Id)

	payload := apns.NewPayload()
	payload.Alert = message
	payload.Badge = 1
	payload.Sound = "bingbong.aiff"

	pn := apns.NewPushNotification()
	pn.DeviceToken = endpoint.DeviceToken
	pn.AddPayload(payload)

	client := apns.NewClient("gateway.sandbox.push.apple.com:2195", "apns-dev-cert.pem", "apns-dev-key-noenc.pem")
	resp := client.Send(pn)

	alert, _ := pn.PayloadString()
	log.Println("  Alert:", alert)
	log.Println("Success:", resp.Success)
	log.Println("  Error:", resp.Error)

}

// Http handler for creates...
func CreateTrigger(w http.ResponseWriter, r *http.Request) {
	log.Println("Received a POST against an ID. Working.")

	vars := mux.Vars(r)
	id := vars["id"]

	// We use the same error every time, as this makes it harder to try and hack from the outside with
	// brute force attempt to get the message. Timing attacks are still an issue however.
	fof := fmt.Sprintf("{\"error\":\"Invalid endpoint/token.\",\"details\":\"Could not find requested endpoint. Please check your configuration.\"}")

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

	// Store the alert, although we need to check the JSON or SQL injection...
	// BASE64 Encode the message!!! Solves the problem, but recoverable.

	// Identify the service we'll use to deliver the message
	serviceId := "UNKNOWN"
	if endpoint.DeviceType == "IOS" {
		serviceId = "Apple Push Notification Service"
		SendNotification(endpoint, message)
	} else if endpoint.DeviceType == "ANDROID" {
		serviceId = "Not implemented!"
	} else if endpoint.DeviceType == "WINDOWS" {
		serviceId = "Not implemented!"
	} else {
		log.Println("Failed to find a device service match: '", endpoint.DeviceType, "'")
		http.Error(w, "{\"error\":\"Could not identify device type.\",\"details\":\"Device type did not match a configured type.\"}", 400)
		return
	}

	// 200 OK!
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "{ \"status\":\"OK\" \"details\": \"Message has been sent to %v.\" }", serviceId)
}

// Http handler for creates...
func ShowTriggers(w http.ResponseWriter, r *http.Request) {
	log.Println("Received a GET. Working.")
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
		log.Println("Using Notific.io to report new registration: ", device_type)
		_, err := http.Post(fmt.Sprintf("http://api.notific.io/"),
			"application/json",
			nil)

		if err != nil {
			log.Println("Failed to notify with notific.io about a new user.")
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

	r.HandleFunc("/{id}", CreateTrigger).Methods("POST")
	r.HandleFunc("/{id}", ShowTriggers).Methods("GET")
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
	apnsCert        *string = flag.String("cert", "", "Apple APNS Certificate")
	apnsPem         *string = flag.String("pem", "", "Apple PEM Key")
	apnsAppId       *string = flag.String("appId", "", "Apple Device/App ID")
	apnsEnvironment *string = flag.String("appleEnv", "development", "Apple Environment")
)

// Entry point.
func main() {
	flag.Parse()
	log.Println("Starting up api.notific.io")
	webServer()
}
