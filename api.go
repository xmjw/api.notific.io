package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"time"
)

// The Endpoint (which later can be grouped on users etc)
type Endpoint struct {
	id    string
	token string
}

// Each notifcation that we send.
type Notification struct {
	id         string
	user_id    string
	payload    string
	status     string
	created_at time.Time
}

// Try and find the API entry in the DB. Then cache as
// necessary.
func FindAPIEntry(id string) (Endpoint, error) {
	// Check cache...

	// Need to open a db connection...

	// Find a record...

	// Load into struct.

	// Cache.
	return Endpoint{}, nil
}

// This checks the user's API token against that in the DB.
func ValidateRequest(token string, user Endpoint) bool {
	return user.token == token
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
	fmt.Println("Received a GET. Working.")
}

// Http handler for creates...
func DeleteTrigger(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received a DELETE. Working.")
}

func webServer() {
	fmt.Println("Building routes to listen on : 5000")

	r := mux.NewRouter()

	r.HandleFunc("/{id}", CreateTrigger).Methods("POST")
	r.HandleFunc("/{id}", ShowTriggers).Methods("GET")
	r.HandleFunc("/{id}", DeleteTrigger).Methods("DELETE")

	http.Handle("/", r)
	http.ListenAndServe(fmt.Sprintf(":%v", 5000), nil)
}

// Entry point.
func main() {
	fmt.Println("Starting up api.notific.io")
	webServer()
}
