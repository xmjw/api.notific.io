package notific

import (
  "time"
  "log"
  "errors"
  "fmt"
  "strings"
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

const QUEUED string = "QUEUED"
const SENT string = "SENT"
const ERROR string = "ERROR"
const REJECTED string = "REJECTED"

// Stores a notification in the database. We base 64 encode the message, not for security, but
// to help protect against SQL injection. This way we are so restrictive on the outside data that
// we store, it should be virtually impossible to perform a SQL injection attack.
func CreateNotification(endpoint *Endpoint, message string, encrypted bool) (*Notification, error) {
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

  return FindNotification(id)
}


// load a notification from the database. Hopefully.
func FindNotification(id string) (*Notification, error) {
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

func FindNotificationsForEndpoint(endpoint *Endpoint, offset int, limit int) (*[]Notification, error) {
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

func UpdateNotification(notification *Notification, status string) {
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
