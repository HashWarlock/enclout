package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalDecisionApproveTransition(t *testing.T) {
	handler, store := newTestHandler(t)
	created, err := store.Create(createInput("dev_1"))
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/connection-requests/"+created.ID+"/local-decision", strings.NewReader(`{"approved":true}`))
	rr := httptest.NewRecorder()
	handler.LocalDecision(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"approved"`) {
		t.Fatalf("expected approved status, got %s", rr.Body.String())
	}
}

func TestLocalDecisionInvalidTransition(t *testing.T) {
	handler, store := newTestHandler(t)
	created, err := store.Create(createInput("dev_1"))
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	_, err = store.SetLocalDecision(created.ID, false)
	if err != nil {
		t.Fatalf("unexpected first decision error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/connection-requests/"+created.ID+"/local-decision", strings.NewReader(`{"approved":true}`))
	rr := httptest.NewRecorder()
	handler.LocalDecision(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", rr.Code)
	}
}
