package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"time"

	"esign/demo"
	"esign/internal/certstore"
	"esign/internal/server"
	"esign/internal/winui"
)

const (
	protocolScheme    = "esign-connector"
	mutexName         = "esign-connector"
	idleCheckInterval = 10 * time.Second
	shutdownTimeout   = 5 * time.Second

	dialogTitle         = "E-imza Bileşeni"
	startFailedTemplate = "E-imza bileşeni başlatılamadı. Zaten çalışıyor olabilir.\n\n%v"
)

// Set at build time: -ldflags "-X main.allowedOrigins=https://portal.example.com -X main.version=1.0.0".
var (
	allowedOrigins = ""
	version        = "dev"
)

type options struct {
	port       int
	origins    []string
	demo       bool
	idle       time.Duration
	unregister bool
}

func main() {
	log.SetFlags(log.LstdFlags)
	if err := run(parseOptions()); err != nil {
		log.Print(err)
		winui.ShowError(dialogTitle, fmt.Sprintf(startFailedTemplate, err))
		os.Exit(1)
	}
}

func parseOptions() options {
	var o options
	flag.IntVar(&o.port, "port", server.DefaultPort, "TCP port on 127.0.0.1")
	flag.Func("allow-origin", "additional allowed web origin (repeatable, for development)", func(v string) error {
		o.origins = append(o.origins, v)
		return nil
	})
	flag.BoolVar(&o.demo, "demo", false, "serve the demo page and open it in the browser")
	flag.DurationVar(&o.idle, "idle-timeout", 30*time.Minute, "exit after this long without requests (0 disables)")
	flag.BoolVar(&o.unregister, "unregister", false, "remove the URL protocol registration and exit")
	flag.Parse()
	o.origins = append(splitOrigins(allowedOrigins), o.origins...)
	return o
}

func run(o options) error {
	if o.unregister {
		return winui.UnregisterProtocol(protocolScheme)
	}

	release, already, err := winui.AcquireSingleInstance(mutexName)
	if err != nil {
		return fmt.Errorf("check for a running instance: %w", err)
	}
	if already {
		return nil
	}
	defer release()

	registerProtocol()

	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.port)))
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", o.port, err)
	}

	activity := newActivityTracker()
	srv := &http.Server{
		Handler:           activity.wrap(server.New(serverConfig(o))),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/", o.port)
	log.Printf("listening on %s (version %s)", url, version)
	if o.demo {
		openBrowser(url)
	}
	return serve(srv, ln, activity, o.idle)
}

func serverConfig(o options) server.Config {
	cfg := server.Config{
		Port:              o.port,
		Version:           version,
		PlatformSupported: runtime.GOOS == "windows",
		AllowedOrigins:    o.origins,
		Store:             systemStore{},
		Confirmer:         nativeConfirmer{},
	}
	if o.demo {
		cfg.Demo = demo.Handler()
	}
	return cfg
}

// registerProtocol is best effort: without it the web app can still reach a running connector.
func registerProtocol() {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("register protocol: %v", err)
		return
	}
	if err := winui.RegisterProtocol(protocolScheme, exe); err != nil {
		log.Printf("register protocol: %v", err)
	}
}

func serve(srv *http.Server, ln net.Listener, activity *activityTracker, idle time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	var idleTick <-chan time.Time
	if idle > 0 {
		t := time.NewTicker(idleCheckInterval)
		defer t.Stop()
		idleTick = t.C
	}
	for {
		select {
		case err := <-serveErr:
			return err
		case <-ctx.Done():
			log.Print("interrupted, shutting down")
			return shutdown(srv)
		case <-idleTick:
			if activity.idleFor() >= idle {
				log.Printf("no requests for %s, shutting down", idle)
				return shutdown(srv)
			}
		}
	}
}

func shutdown(srv *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func splitOrigins(s string) []string {
	var out []string
	for _, o := range strings.Split(s, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, o)
		}
	}
	return out
}

type nativeConfirmer struct{}

func (nativeConfirmer) Confirm(title, message string) bool { return winui.Confirm(title, message) }

type systemStore struct{}

func (systemStore) List() ([]certstore.Certificate, error)   { return certstore.List() }
func (systemStore) Open(id string) (certstore.Signer, error) { return certstore.Open(id) }
