package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetAttestationBundle(t *testing.T) {
	handler, store := newTestHandler(t)
	created, err := store.Create(createInput("dev_1"))
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	_, err = store.SetLocalDecision(created.ID, true)
	if err != nil {
		t.Fatalf("unexpected approval error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/connection-requests/"+created.ID+"/attestation-bundle", nil)
	rr := httptest.NewRecorder()
	handler.AttestationBundle(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"signature"`) {
		t.Fatalf("expected signature in response, got %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"kid":"v1"`) {
		t.Fatalf("expected signing kid in response, got %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"report_data_expected_sha256"`) {
		t.Fatalf("expected report-data hash in response, got %s", rr.Body.String())
	}
}

func TestGetAttestationBundleRequiresApproval(t *testing.T) {
	handler, store := newTestHandler(t)
	created, err := store.Create(createInput("dev_1"))
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/connection-requests/"+created.ID+"/attestation-bundle", nil)
	rr := httptest.NewRecorder()
	handler.AttestationBundle(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", rr.Code)
	}
}
