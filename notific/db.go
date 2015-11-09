package notific

import (
  "database/sql"
  _ "github.com/lib/pq"
  "log"
)

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
