// Command mirage-chaff is a "cushion" server that sits behind AdGuard Home and
// selectively intercepts a curated subset of domains: it terminates TLS with a
// dynamically issued leaf, applies a policy (stub / forward-scrubbed /
// forward-mimic / forward-asis / passthrough) and serves decoy responses so
// anti-adblock detection is satisfied while trackers receive no real traffic.
//
// Phase 0 provides the runnable skeleton: subcommands, config load+validate, and
// an admin-independent health/metrics listener. The interception data path is
// filled in from Phase 1 onward (see README / design doc).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/vnoiram/mirage-chaff/internal/admin"
	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/server"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.0.0-dev"

const defaultConfigPath = "/etc/mirage-chaff/mirage-chaff.conf"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "check":
		os.Exit(cmdCheck(os.Args[2:]))
	case "admin-bootstrap":
		os.Exit(cmdAdminBootstrap(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Printf("mirage-chaff %s\n", version)
		os.Exit(0)
	case "help", "-h", "--help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "mirage-chaff: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mirage-chaff — selective anti-adblock / privacy cushion server

Usage:
  mirage-chaff run   [-config PATH]   Run the server (foreground; systemd-managed in production).
  mirage-chaff check [-config PATH]   Validate config + policy.d + catalog, then exit (nginx -t style).
  mirage-chaff admin-bootstrap [-config PATH]
                                      Create the initial local admin account if needed.
  mirage-chaff version                Print version and exit.

Default config path: `+defaultConfigPath+`
`)
}

// cmdCheck implements the D-1 "config test" subcommand: load and validate the
// full configuration without starting any listener, so hand-editors and
// install.sh can catch mistakes before a reload/restart brings the service down.
func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to mirage-chaff.conf")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if _, err := os.Stat(*cfgPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "config load failed: %s does not exist\n", *cfgPath)
			return 1
		}
		fmt.Fprintf(os.Stderr, "config load failed: stat %s: %v\n", *cfgPath, err)
		return 1
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		return 1
	}
	if err := cfg.Check(); err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}
	fmt.Printf("ok: %s is valid\n", *cfgPath)
	return 0
}

func cmdAdminBootstrap(args []string) int {
	fs := flag.NewFlagSet("admin-bootstrap", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to mirage-chaff.conf")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		return 1
	}
	if err := cfg.Check(); err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}
	if !cfg.Admin.Enabled {
		fmt.Println("admin disabled; bootstrap skipped")
		return 0
	}

	store, err := admin.OpenStore(filepath.Join(cfg.Paths.StateDir, "admin", "admin.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin bootstrap failed: %v\n", err)
		return 1
	}
	password, created, err := admin.BootstrapInitialAdmin(store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin bootstrap failed: %v\n", err)
		return 1
	}
	if !created {
		fmt.Println("admin users already exist; bootstrap skipped")
		return 0
	}
	fmt.Printf("created initial admin account 'admin'\nTEMPORARY PASSWORD: %s\nchange on first login\n", password)
	return 0
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to mirage-chaff.conf")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		return 1
	}
	if err := cfg.Check(); err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}

	// SIGTERM/SIGINT trigger graceful shutdown; SIGHUP triggers reload of
	// policy.d/catalog (handled inside server.Run).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv := server.New(cfg, version, *cfgPath)
	if err := srv.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "server exited with error: %v\n", err)
		return 1
	}
	return 0
}
