package notific

import (
  "encoding/base64"
  "log"
)

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
