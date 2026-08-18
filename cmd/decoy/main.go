// decoy is the Decoy product binary: canary tokens and honeypots on Sentinel
// Core.
//
//	decoy                        # dashboard on 127.0.0.1:8424
//	decoy -base-url https://decoy.example.com   # public base for tokens
//	decoy -dns-zone canary.example.com -dns-listen :53   # enable DNS tokens
//
// Plant a trap from the dashboard, then wait. A legitimate user never touches
// it — so when one trips, someone is where they shouldn't be, and you know in
// seconds.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // dev driver; release swaps to modernc.org/sqlite

	"github.com/nizartuanku/decoy/decoy"
	"github.com/nizartuanku/decoy/license"
	"github.com/nizartuanku/decoy/notify"
	"github.com/nizartuanku/decoy/sched"
	"github.com/nizartuanku/decoy/store"
	"github.com/nizartuanku/decoy/web"
)

// issuerPublicKeyB64 is baked in at build time by the release process.
// Empty → every key invalid → permanent free edition (this open-source build).
var issuerPublicKeyB64 = ""

// decoyTierLimits is the generic per-tier table (total traps as MaxTargets +
// channels/retention). The finer token-vs-honeypot-vs-advanced split lives in
// decoy.DefaultCaps.
var decoyTierLimits = map[license.Tier]license.Limits{
	license.TierFree: {MaxTargets: 4, RetentionDays: 14, Channels: []string{"webhook"}},
	license.TierPro: {MaxTargets: 60, RetentionDays: 365,
		Channels: []string{"webhook", "email", "slack", "telegram"}, CustomInterval: true, ScanNow: true},
	license.TierTeam: {MaxTargets: 0, RetentionDays: 0,
		Channels:  []string{"webhook", "email", "slack", "telegram", "pagerduty", "teams"},
		MultiUser: true, CustomInterval: true, ScanNow: true},
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8424", "dashboard listen address")
	dbPath := flag.String("db", "decoy.db", "SQLite database path")
	licFile := flag.String("license", "decoy-license.key", "license key file")
	webhook := flag.String("webhook", "", "webhook URL for alerts")
	baseURL := flag.String("base-url", "", "public base URL tokens are reached at (default http://<listen>)")
	honeypotBind := flag.String("honeypot-bind", "0.0.0.0", "interface honeypots bind to")
	dnsZone := flag.String("dns-zone", "", "delegated DNS zone for DNS tokens (empty = disabled)")
	dnsListen := flag.String("dns-listen", ":53", "UDP address for the DNS responder (only if -dns-zone set)")
	flag.Parse()

	base := *baseURL
	if base == "" {
		base = "http://" + *listen
	}

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	st, err := store.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	decoyStore, err := decoy.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	engine := store.NewEngine(st)

	module := decoy.New(decoyStore)
	scheduler := sched.New(engine, sched.Config{})
	if err := scheduler.Register(module); err != nil {
		fatal(err.Error())
	}

	// Alerts flush fast — a canary that waits 30s is still a canary, but 5s is
	// better, and a scanner's burst still merges into one digest.
	var disp *notify.Dispatcher
	if *webhook != "" {
		disp = notify.NewDispatcher(notify.Config{FlushInterval: 5 * time.Second},
			&notify.WebhookChannel{URL: *webhook})
		notify.BindScheduler(scheduler, disp)
		defer disp.Close()
	}

	sink := &decoy.TripSink{Store: st, Decoy: decoyStore, Disp: disp}
	supervisor := decoy.NewSupervisor(sink)
	supervisor.BindHost = *honeypotBind
	defer supervisor.StopAll()

	// Optional DNS responder for DNS-token traps.
	if *dnsZone != "" {
		dns := &decoy.DNSResponder{Store: decoyStore, Sink: sink}
		if err := dns.Start(*dnsListen); err != nil {
			fmt.Fprintf(os.Stderr, "decoy: DNS responder disabled: %v\n", err)
		} else {
			defer dns.Stop()
			fmt.Printf("DNS responder: %s (zone %s)\n", *dnsListen, *dnsZone)
		}
	}

	// Restore armed traps: register each as a scheduler target and re-bind
	// honeypot listeners so state survives a restart.
	if deps, err := decoyStore.ListDeployments(); err == nil {
		for _, d := range deps {
			if _, err := scheduler.AddTarget(decoy.ModuleID, d.ID); err != nil {
				fmt.Fprintf(os.Stderr, "decoy: skipping trap %q: %v\n", d.ID, err)
			}
			if d.Kind == decoy.KindHoneypot {
				if err := supervisor.Start(d); err != nil {
					fmt.Fprintf(os.Stderr, "decoy: honeypot %q (port %d) not bound: %v\n", d.Label, d.Port, err)
				}
			}
		}
	}

	var pub ed25519.PublicKey
	if issuerPublicKeyB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(issuerPublicKeyB64); err == nil {
			pub = ed25519.PublicKey(b)
		}
	}
	server := web.NewServer(module.Describe(), st, scheduler, pub, *licFile)
	server.Targets = st
	server.TierLimits = decoyTierLimits

	manager := &decoy.Manager{Store: decoyStore, BaseURL: base}
	console := &decoy.Console{
		Store:   decoyStore,
		Manager: manager,
		DNSZone: *dnsZone,
		Caps: func() decoy.Caps {
			if c, ok := decoy.DefaultCaps[server.Activation().Tier]; ok {
				return c
			}
			return decoy.DefaultCaps[license.TierFree]
		},
		OnCreate: func(d decoy.Deployment) error {
			if d.Kind == decoy.KindHoneypot {
				if err := supervisor.Start(d); err != nil {
					return err
				}
			}
			if _, err := scheduler.AddTarget(decoy.ModuleID, d.ID); err != nil {
				if d.Kind == decoy.KindHoneypot {
					supervisor.Stop(d.ID)
				}
				return err
			}
			return nil
		},
		OnDelete: func(d decoy.Deployment) {
			if d.Kind == decoy.KindHoneypot {
				supervisor.Stop(d.ID)
			}
			scheduler.RemoveTarget(decoy.ModuleID, d.ID)
		},
	}
	tokens := &decoy.TokenHandler{Store: decoyStore, Sink: sink}
	server.ExtraRoutes = func(mux *http.ServeMux) {
		console.Register(mux, tokens)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := scheduler.Start(ctx); err != nil {
		fatal(err.Error())
	}

	httpSrv := &http.Server{Addr: *listen, Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(sc)
		scheduler.Stop()
	}()

	fmt.Printf("Decoy %s — %s edition\n", module.Describe().Version, server.Activation().Tier)
	fmt.Printf("Dashboard: http://%s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "decoy: "+msg)
	os.Exit(1)
}
