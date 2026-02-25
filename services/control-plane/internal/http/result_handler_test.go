package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResultVerificationFailedTransition(t *testing.T) {
	handler, store := newTestHandler(t)
	created, err := store.Create(createInput("dev_1"))
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	_, err = store.SetLocalDecision(created.ID, true)
	if err != nil {
		t.Fatalf("unexpected approval error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/connection-requests/"+created.ID+"/result", strings.NewReader(`{"status":"verification_failed","reason_code":"ReportDataMismatch"}`))
	rr := httptest.NewRecorder()
	handler.Result(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"verification_failed"`) {
		t.Fatalf("expected verification_failed in body, got %s", rr.Body.String())
	}
}

func TestResultRequiresApprovedState(t *testing.T) {
	handler, store := newTestHandler(t)
	created, err := store.Create(createInput("dev_1"))
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/connection-requests/"+created.ID+"/result", strings.NewReader(`{"status":"connected"}`))
	rr := httptest.NewRecorder()
	handler.Result(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", rr.Code)
	}
}
