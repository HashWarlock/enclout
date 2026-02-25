package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"enclout/services/control-plane/internal/config"
	handlers "enclout/services/control-plane/internal/http"
	"enclout/services/control-plane/internal/openclaw"
	"enclout/services/control-plane/internal/requests"
	"enclout/services/control-plane/internal/signing"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	signer, err := signing.NewEd25519SignerFromSeedB64(cfg.SigningKeyB64)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	store := requests.NewInMemoryStore()
	bundles := handlers.NewStaticBundleSource(loadBundleTemplatesFromEnv())
	api := handlers.NewHandler(store, signer, bundles)
	openClawHandler := openclaw.NewIntentHandler(store)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/connection-requests", methodOnly(http.MethodPost, api.CreateRequest))
	mux.HandleFunc("/v1/connection-requests/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/local-decision") && r.Method == http.MethodPost:
			api.LocalDecision(w, r)
		case strings.HasSuffix(r.URL.Path, "/result") && r.Method == http.MethodPost:
			api.Result(w, r)
		case strings.HasSuffix(r.URL.Path, "/attestation-bundle") && r.Method == http.MethodGet:
			api.AttestationBundle(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/v1/devices/", methodOnly(http.MethodGet, api.ListPendingRequestsForDevice))
	mux.HandleFunc("/v1/openclaw/intents", methodOnly(http.MethodPost, openClawHandler.Handle))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("control-plane listening on %s", cfg.BindAddr)
	if err := http.ListenAndServe(cfg.BindAddr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func methodOnly(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "method_not_allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func loadBundleTemplatesFromEnv() map[string]handlers.BundleTemplate {
	raw := os.Getenv("CONNECTOR_BUNDLE_TEMPLATES_JSON")
	if raw == "" {
		return map[string]handlers.BundleTemplate{}
	}

	out := map[string]handlers.BundleTemplate{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		log.Printf("invalid CONNECTOR_BUNDLE_TEMPLATES_JSON, using empty set: %v", err)
		return map[string]handlers.BundleTemplate{}
	}
	return out
}
