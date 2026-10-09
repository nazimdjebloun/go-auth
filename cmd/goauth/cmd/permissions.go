package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/sqldriver"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/spf13/cobra"
)

func init() { rootCmd.AddCommand(newPermissionsCommand()) }

func newPermissionsCommand() *cobra.Command {
	group := &cobra.Command{Use: "permissions", Short: "Manage optional library permission definitions"}
	group.AddCommand(&cobra.Command{Use: "catalog", Short: "Print the fixed library catalog without connecting to a database", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(service.AppLibraryPermissionCatalog())
	}})
	for _, seed := range []bool{true, false} {
		name := "update"
		if seed {
			name = "seed"
		}
		command := &cobra.Command{Use: name, Short: "Atomically install or remove selected library permissions", Args: cobra.NoArgs}
		command.Flags().String("driver", "", "Database driver (postgres, sqlite, mysql)")
		command.Flags().String("dsn", "", "Database DSN")
		command.Flags().String("actor-id", "", "Current protected administrator ID for attribution")
		if seed {
			command.Flags().StringSlice("keys", nil, "Catalog keys to install")
			command.Flags().Bool("all", false, "Explicitly install every catalog key")
		} else {
			command.Flags().StringSlice("create", nil, "Catalog keys to install")
			command.Flags().StringSlice("delete", nil, "Catalog keys to remove, including all grants")
		}
		for _, flag := range []string{"driver", "dsn", "actor-id"} {
			mustMarkFlagRequired(command, flag)
		}
		command.RunE = func(cmd *cobra.Command, _ []string) error {
			var create, remove []string
			if seed {
				create, _ = cmd.Flags().GetStringSlice("keys")
				all, _ := cmd.Flags().GetBool("all")
				if all && len(create) > 0 {
					return fmt.Errorf("choose --all or --keys")
				}
				if all {
					for _, p := range service.AppLibraryPermissionCatalog() {
						create = append(create, p.Key)
					}
				}
			} else {
				create, _ = cmd.Flags().GetStringSlice("create")
				remove, _ = cmd.Flags().GetStringSlice("delete")
			}
			if len(create)+len(remove) == 0 {
				return fmt.Errorf("select at least one catalog key")
			}
			driver, _ := cmd.Flags().GetString("driver")
			dsn, _ := cmd.Flags().GetString("dsn")
			actorID, _ := cmd.Flags().GetString("actor-id")
			sqlDriver := sqldriver.SQLName(driver)
			if sqlDriver == "sqlite" || sqlDriver == "sqlite3" {
				var err error
				dsn, err = sqldriver.SQLiteForeignKeyDSN(sqlDriver, dsn)
				if err != nil {
					return err
				}
			}
			db, err := sql.Open(sqlDriver, dsn)
			if err != nil {
				return err
			}
			defer func() {
				if err := db.Close(); err != nil {
					slog.Error("goauth: close permission database", "err", err)
				}
			}()
			if sqlDriver == "sqlite" || sqlDriver == "sqlite3" {
				db.SetMaxOpenConns(1)
			}
			if err := db.PingContext(cmd.Context()); err != nil {
				return err
			}
			store := sqlstore.NewDB(db, sqlDriver)
			permissions, _, _ := cliAppPermissions(store)
			result, err := service.NewAppLibraryPermissionCLIProvisioner(permissions).Update(cmd.Context(), api.UpdateAppLibraryPermissionsInput{Actor: api.AppPermissionActor{UserID: actorID}, Create: create, Delete: remove})
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		}
		group.AddCommand(command)
	}
	return group
}

// CLI writes use the same transaction writer with database-only durable audit.
// No dispatcher is started: this command configures no external delivery sinks.
func cliAppPermissions(db *sqlstore.DB) (*service.AppPermissionsService, *sqlstore.UserRepository, *sqlstore.AppPermissionsRepository) {
	users := sqlstore.NewUserRepository(db).WithAppPermissions()
	repo := sqlstore.NewAppPermissionsRepository(db)
	publisher := audit.NewService(audit.ServiceConfig{EnqueueFailureMode: func(audit.Event) audit.FailureMode { return audit.FailureClosed }}, db, sqlstore.NewRecordRepository(db), nil, slog.Default())
	s := service.NewAppPermissionsService(db, users, nil, nil, repo, repo, repo, repo, service.AppPermissionsServiceConfig{Audit: publisher})
	return s, users, repo
}

func seedAppAdministrator(ctx context.Context, user *domain.User, force bool, db *sqlstore.DB) error {
	s, users, repo := cliAppPermissions(db)
	return users.WithAdminGuard(ctx, func(ctx context.Context) error {
		revision, err := repo.AppStateRevision(ctx)
		if err != nil {
			return err
		}
		if revision == 0 {
			if err := users.Create(ctx, user); err != nil {
				return err
			}
			if err := s.Initialize(ctx, api.InitializeAppPermissionsInput{AdministratorUserID: user.ID}); err != nil {
				return err
			}
			stored, err := users.GetByIDForUpdate(ctx, user.ID)
			if err != nil {
				return err
			}
			*user = *stored
			return nil
		}
		if !force {
			return fmt.Errorf("app authorization is already initialized; pass --force to create another protected administrator")
		}
		if err := repo.LockAppState(ctx); err != nil {
			return err
		}
		role, err := repo.RoleBySlug(ctx, "admin")
		if err != nil {
			return err
		}
		if role == nil || !role.IsAdmin() {
			return domain.ErrAppRoleNotFound
		}
		user.AppRoleID = &role.ID
		user.AppRoleAssignmentRevision = 1
		if err := users.Create(ctx, user); err != nil {
			return err
		}
		if err := repo.BumpAppState(ctx); err != nil {
			return err
		}
		e := audit.NewEvent(audit.EventAdminUserCreated, audit.WithActor(user.ID))
		e.Success = true
		e.Metadata = map[string]any{"source": "cli", "roleId": *user.AppRoleID, "createdAt": time.Now().UTC()}
		publisher := audit.NewService(audit.ServiceConfig{EnqueueFailureMode: func(audit.Event) audit.FailureMode { return audit.FailureClosed }}, db, sqlstore.NewRecordRepository(db), nil, slog.Default())
		return publisher.Record(ctx, e)
	})
}
