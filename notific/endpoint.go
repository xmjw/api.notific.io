package notific

import (
  "time"
  "errors"
  "strings"
  "fmt"
  "log"
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

// Creates a new registration...
func CreateEndpoint(deviceType string, deviceId string, deviceToken string) (*Endpoint, error) {
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

// Try and find the API entry in the DB. Then cache as necessary.
func FindEndpoint(id string) (*Endpoint, error) {
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