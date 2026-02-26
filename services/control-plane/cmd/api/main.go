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

	signerSet, err := signing.NewSignerSetFromSeedMap(cfg.SigningKeys, cfg.SigningActiveKID)
	if err != nil {
		log.Fatalf("create signer set: %v", err)
	}

	store, err := requests.NewFileStore(cfg.StorePath)
	if err != nil {
		log.Fatalf("create persistent store: %v", err)
	}
	bundles := handlers.NewStaticBundleSource(loadBundleTemplatesFromEnv())
	api := handlers.NewHandler(store, signerSet, bundles)
	openClawHandler := openclaw.NewIntentHandler(store)
	requireAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return handlers.RequireBearerToken(cfg.APIToken, next)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/connection-requests", requireAuth(methodOnly(http.MethodPost, api.CreateRequest)))
	mux.HandleFunc("/v1/connection-requests/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/local-decision") && r.Method == http.MethodPost:
			requireAuth(api.LocalDecision)(w, r)
		case strings.HasSuffix(r.URL.Path, "/result") && r.Method == http.MethodPost:
			requireAuth(api.Result)(w, r)
		case strings.HasSuffix(r.URL.Path, "/attestation-bundle") && r.Method == http.MethodGet:
			requireAuth(api.AttestationBundle)(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/v1/install-sessions", requireAuth(methodOnly(http.MethodPost, api.CreateInstallSession)))
	mux.HandleFunc("/v1/install-sessions/redeem", requireAuth(methodOnly(http.MethodPost, api.RedeemInstallToken)))
	mux.HandleFunc("/v1/install-sessions/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/approval") && r.Method == http.MethodPost:
			requireAuth(api.InstallSessionApproval)(w, r)
		case strings.HasSuffix(r.URL.Path, "/result") && r.Method == http.MethodPost:
			requireAuth(api.InstallSessionResult)(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/v1/devices/", requireAuth(methodOnly(http.MethodGet, api.ListPendingRequestsForDevice)))
	mux.HandleFunc("/v1/openclaw/intents", requireAuth(methodOnly(http.MethodPost, openClawHandler.Handle)))
	mux.HandleFunc("/v1/signing-keys", requireAuth(methodOnly(http.MethodGet, api.SigningKeys)))
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
