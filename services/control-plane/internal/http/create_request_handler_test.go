package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateRequestHandler(t *testing.T) {
	handler, _ := newTestHandler(t)

	body := `{"openclaw_user_id":"usr_1","device_id":"dev_1","connector_id":"conn_1","source_channel":"slack"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/connection-requests", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.CreateRequest(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"status":"pending_local_confirm"`) {
		t.Fatalf("expected pending status in response, got %s", rr.Body.String())
	}
}

func TestListPendingRequestsForDevice(t *testing.T) {
	handler, store := newTestHandler(t)
	_, err := store.Create(createInput("dev_1"))
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/devices/dev_1/pending-requests", nil)
	rr := httptest.NewRecorder()
	handler.ListPendingRequestsForDevice(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"device_id":"dev_1"`) {
		t.Fatalf("expected device id in body, got %s", rr.Body.String())
	}
}
