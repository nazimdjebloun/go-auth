package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/nazimdjebloun/go-auth"
	_ "github.com/lib/pq"
)

func main() {
	cmd := flag.String("cmd", "", "Command: migrate, init-schema")
	dsn := flag.String("dsn", os.Getenv("AUTH_DSN"), "PostgreSQL DSN")
	flag.Parse()

	switch *cmd {
	case "migrate":
		if *dsn == "" {
			log.Fatal("DSN is required. Set AUTH_DSN env or use --dsn")
		}
		db, err := sql.Open("postgres", *dsn)
		if err != nil {
			log.Fatalf("Failed to connect: %v", err)
		}
		defer db.Close()

		if err := migrate(db, goauth.EmbeddedSchema); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Migration complete!")

	case "init-schema":
		fmt.Println(goauth.EmbeddedSchema)

	default:
		fmt.Println(`Usage: go-auth --cmd <command> [options]

Commands:
  migrate       Run database migrations
  init-schema   Print the embedded schema to stdout

Options:
  --dsn string     PostgreSQL DSN (or AUTH_DSN env)`)
	}
}

func migrate(db *sql.DB, schema string) error {
	for _, stmt := range splitSQL(schema) {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("migration failed: %w\nStatement: %s", err, truncate(stmt, 100))
		}
		fmt.Println("OK:", truncate(stmt, 80))
	}
	return nil
}

func splitSQL(s string) []string {
	var result []string
	current := strings.Builder{}
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		current.WriteString(line + "\n")
		if strings.HasSuffix(trimmed, ";") {
			result = append(result, current.String())
			current.Reset()
		}
	}
	return result
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(s[:n]) + "..."
}
