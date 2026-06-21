package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/nazimdjebloun/go-auth"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func main() {
	cmd := flag.String("cmd", "", "Command: migrate, init-schema")
	dsn := flag.String("dsn", os.Getenv("AUTH_DSN"), "Database DSN")
	driver := flag.String("driver", "postgres", "Database driver (postgres, mysql, sqlite3)")
	flag.Parse()

	switch *cmd {
	case "migrate":
		if *dsn == "" {
			log.Fatal("DSN is required. Set AUTH_DSN env or use --dsn")
		}
		db, err := sql.Open(*driver, *dsn)
		if err != nil {
			log.Fatalf("Failed to connect: %v", err)
		}
		defer db.Close()

		schema, err := goauth.GetSchema(*driver)
		if err != nil {
			log.Fatal(err)
		}
		for _, stmt := range goauth.SplitSQL(schema) {
			if _, err := db.Exec(stmt); err != nil {
				log.Fatalf("Migration failed: %v\nStatement: %s", err, stmt)
			}
			fmt.Println("OK:", stmt)
		}
		fmt.Println("Migration complete!")

	case "init-schema":
		schema, err := goauth.GetSchema(*driver)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(schema)

	default:
		fmt.Println(`Usage: go-auth --cmd <command> [options]

Commands:
  migrate       Run database migrations
  init-schema   Print the embedded schema to stdout

Options:
  --dsn string     Database DSN (or AUTH_DSN env)
  --driver string  Database driver: postgres, mysql, sqlite3 (default "postgres")`)
	}
}
