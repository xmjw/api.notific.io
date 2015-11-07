package notific

import (
  "regexp"
  "log"
  "math/rand"
  "code.google.com/p/go-uuid/uuid"
  "time"
)  

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