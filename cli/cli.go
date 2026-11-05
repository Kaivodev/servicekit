// Package cli provides command dispatch; individual services supply composition
// callbacks and own their databases, migrations and business registrations.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Kaivodev/servicekit/migration"
	"github.com/golang-migrate/migrate/v4"
)

type Version struct {
	Service string `json:"service"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
	Dirty   string `json:"dirty"`
}

type Commands struct {
	Name          string
	Version       Version
	Serve         func(context.Context) error
	Healthcheck   func(context.Context) error
	OpenMigration func() (*migration.Runner, error)
}

func Run(args []string, commands Commands, output io.Writer) error {
	if output == nil {
		output = os.Stdout
	}
	if len(args) == 0 {
		args = []string{"serve"}
	}
	switch args[0] {
	case "help", "-h", "--help":
		_, err := fmt.Fprintf(output, "Usage: %s [serve | version | healthcheck | migrate up|down|version]\n", commands.Name)
		return err
	case "version":
		if len(args) != 1 {
			return errors.New("version takes no arguments")
		}
		return json.NewEncoder(output).Encode(commands.Version)
	case "serve":
		if len(args) != 1 || commands.Serve == nil {
			return errors.New("invalid serve command")
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return commands.Serve(ctx)
	case "healthcheck":
		if len(args) != 1 || commands.Healthcheck == nil {
			return errors.New("invalid healthcheck command")
		}
		return commands.Healthcheck(context.Background())
	case "migrate":
		if len(args) != 2 || commands.OpenMigration == nil {
			return errors.New("usage: migrate up|down|version (down removes the latest migration)")
		}
		if args[1] != "up" && args[1] != "down" && args[1] != "version" {
			return errors.New("unknown migration operation")
		}
		return migrateCommand(args[1], commands.OpenMigration, output)
	default:
		return errors.New("unknown command; use help")
	}
}

func migrateCommand(operation string, open func() (*migration.Runner, error), output io.Writer) (err error) {
	runner, err := open()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, runner.Close()) }()
	switch operation {
	case "up":
		return runner.Up()
	case "down":
		return runner.DownOne()
	default:
		version, dirty, err := runner.Version()
		if errors.Is(err, migrate.ErrNilVersion) {
			_, err = fmt.Fprintln(output, "database has no applied migration")
			return err
		}
		if err != nil {
			return errors.New("read database migration version failed")
		}
		_, err = fmt.Fprintf(output, "version=%d dirty=%t\n", version, dirty)
		return err
	}
}
