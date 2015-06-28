package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/gorilla/mux"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"time"
)

// The Endpoint (which later can be grouped on users etc)
type Endpoint struct {
	Id         string
	Token      string
	DeviceId   string
	CreatedAt  time.Time
	DeviceType string
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
	db, err := sql.Open("postgres", *databaseConnectionString)
	if err != nil {
		log.Fatal("Failed to open database connection. The server will shut down: %v", err)
	}
	return db
}

// Try and find the API entry in the DB. Then cache as
// necessary.
func FindAPIEntry(id string) (Endpoint, error) {

	// Need to open a db connection...

	// Find a record...

	// Load into struct.

	return Endpoint{}, nil
}

func check_device_type(t string) bool {
	if t == "IOS" || t == "ANDROID" || t == "WINDOWS" {
		return true
	} else {
		return false
	}
}

func check_uuid(val string) bool {
	r := regexp.MustCompile("^[a-z0-9]{8}-[a-z0-9]{4}-[1-5][a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12}$")
	return r.MatchString(val)
}

// 'charabet' an alphabet with all meaningful glyphs, i.e., numbers and letters.
const charabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Generates 8 x alphachar string as a unique ID.
func create_id() string {
	var bytes = make([]byte, 8)
	r := rand.New(rand.NewSource(time.Now().Unix()))
	for k, _ := range bytes {
		bytes[k] = charabet[r.Intn(len(charabet))]
	}
	return string(bytes)
}

// Creates a new registration...
func createEndpoint(device_type string, device_id string) (*Endpoint, error) {
	c := DbConnection()

	if !check_uuid(device_type) {
		return nil, errors.New("Invalid Device ID.")
	}

	if !check_device_type(device_type) {
		return nil, errors.New("Invalid Device type.")
	}

	endpoint_id := create_id()
	endpoint_token := create_id()

	c.QueryRow("INSERT INTO endpoints () VALUES (\"%v\")",
		device_type,
		device_id,
		endpoint_id,
		endpoint_token,
		time.Now())

	return &Endpoint{Id: endpoint_id, Token: endpoint_token, DeviceId: device_id, DeviceType: device_type}, nil
}

// Enhanced security, this is the user we think it is, using the app we think
// they're using. So we let them see old notifications, and allow recycling etc.
func AuthenticateRequest(device string, token string, user Endpoint) bool {
	return false
}

// This checks the user's API token against that in the DB.
// It means that we can trigger the endpoint. NOT that we can do anything else.
// For administration of this endpoint, see AuthenticateRequest().
func ValidateRequest(token string, user Endpoint) bool {
	return user.Token == token
}

// Store the request in the DB, and send to APNS
func RecordNotification(user Endpoint, payload string) bool {
	return false
}

// Http handler for creates...
func CreateTrigger(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received a POST. Working.")
}

// Http handler for creates...
func ShowTriggers(w http.ResponseWriter, r *http.Request) {
	id := create_id()
	fmt.Println("Received a GET. Working: %v", id)
}

// Http handler for creates...
func DeleteTrigger(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received a DELETE. Working.")
}

// If a user has miraculously started getting spam on this endpoint,
// this allows them to simply reset their tokens, and stop it.
// Like the read requests, this route requires the device ID, or anyone
// could reset your token. Which is obviously bad.
func RecycleToken(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received a PATCH. Will recycle token if request is valid.")
}

// When a new mobile app is registering itself, we use this.
func RegisterDevice(w http.ResponseWriter, r *http.Request) {
	log.Println("Registering a new Device!")

	data, err := simplejson.NewFromReader(r.Body)

	if err != nil {
		log.Println("Failed to parse incoming JSON: %v", err)
		http.Error(w, fmt.Sprintf("{\"error\":\"JSON Parse Failure\",\"details\":\"%v\"}", err), 500)
	}

	device_type := data.Get("deviceType").MustString()
	device_id := data.Get("deviceId").MustString()

	log.Print("A new device registration will be created for an '%v'", device_type)

	endpoint, err := createEndpoint(device_type, device_id)

	if err != nil {
		log.Println("Failed to create a new endpoint: %v", err)
		http.Error(w, fmt.Sprintf("{\"error\":\"Failed to create a new endpoint.\",\"details\":\"%v\"}", err), 500)
	}

	// Off in the background we'll report a new user using this software.
	// How's that for dogfood?
	go func(device_type string) {
		log.Println("Using Notific.io to report new registration: %v", err)
		_, err := http.Post(fmt.Sprintf("http://api.notific.io/"),
			"application/json",
			nil)

		if err != nil {
			log.Println("Failed to notify with notific.io about a new user.")
		}
	}(device_type)

	fmt.Fprintf(w, "{ \"id\":\"%v\" \"token\": \"%v\" }", endpoint.Id, endpoint.Token)
}

func EchoOK(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK")
}

// Core Web stuff for routing.
func webServer() {
	log.Println("Building routes to listen on: ", *httpPort)

	r := mux.NewRouter()

	r.HandleFunc("/OK", EchoOK).Methods("GET")
	r.HandleFunc("/{id}", CreateTrigger).Methods("POST")
	r.HandleFunc("/{id}", ShowTriggers).Methods("GET")
	r.HandleFunc("/{id}", DeleteTrigger).Methods("DELETE")
	r.HandleFunc("/{id}/recycle", RecycleToken).Methods("PATCH")
	r.HandleFunc("/", RegisterDevice).Methods("POST")

	http.ListenAndServe(fmt.Sprintf(":%d", 5000), nil)
}

var (
	databaseConnectionString *string = flag.String("database", "", "Postgres Database Connection String")
	httpPort                 *int    = flag.Int("port", 5000, "HTTP Port to listen on, defaults to 5000")
	notificToken             *string = flag.String("token", "", "Notific.io token")
	notificEndpoint          *string = flag.String("endpoint", "", "Notific.io endpoint ID")
	apnsCert                 *string = flag.String("cert", "", "Apple APNS Certificate")
	apnsPem                  *string = flag.String("pem", "", "Apple PEM Key")
	apnsAppId                *string = flag.String("appId", "", "Apple Device/App ID")
)

// Entry point.
func main() {
	flag.Parse()
	log.Println("Starting up api.notific.io")
	webServer()
}
