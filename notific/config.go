package notific

import "flag"

var (
  dbConStr        *string = flag.String("database", "", "Postgres Database Connection String")
  httpPort        *string = flag.String("port", "5000", "HTTP Port to listen on, defaults to 5000")
  notificToken    *string = flag.String("token", "", "Notific.io token")
  notificEndpoint *string = flag.String("endpoint", "", "Notific.io endpoint ID")
  apnsHost        *string = flag.String("apns", "gateway.sandbox.push.apple.com:2195", "Apple APNS Host")
  apnsCert        *string = flag.String("cert", "", "Apple APNS Certificate")
  apnsKey         *string = flag.String("pem", "", "Apple PEM Key")
)