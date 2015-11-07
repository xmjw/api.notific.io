package notific

import (
  gojson "encoding/json"
  "net/http"
  "log"
  "github.com/anachronistic/apns"
  "github.com/gorilla/mux"
  "fmt"
  "github.com/bitly/go-simplejson"
  "strconv"
)


// Core Web stuff for routing.
func WebServer() {
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

  notif, err := FindNotification(id)

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

  endpoint, err := FindEndpoint(id)

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

  notif, err := CreateNotification(endpoint, message, false)

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
    //  serviceId = "Not implemented!"
    // } else if endpoint.DeviceType == "WINDOWS" {
    //  serviceId = "Not implemented!"
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

  endpoint, err := FindEndpoint(id)

  if err != nil {
    log.Println("Failed to find endpoint: ", id)
    http.Error(w, fof, 404)
  }

  if validateRequest(token, endpoint) == false {
    log.Println("Token was not valid against the endpoint: ", token)
    http.Error(w, fof, 401)
  }

  notifications, err := FindNotificationsForEndpoint(endpoint, offset, limit)

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

  endpoint, err := CreateEndpoint(device_type, device_id, device_token)

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