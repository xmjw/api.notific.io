package notific

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
