package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"enclout/services/control-plane/internal/requests"
)

func TestCreateInstallSessionHandlerIssuesRequestedSessionAndToken(t *testing.T) {
	handler, _ := newTestHandler(t)

	body := `{"openclaw_user_id":"usr_1","device_id":"dev_1","connector_id":"conn_1","source_channel":"telegram"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/install-sessions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.CreateInstallSession(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d body=%s", rr.Code, rr.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unexpected json response: %v", err)
	}
	if out["status"] != "requested" {
		t.Fatalf("expected requested status, got %#v", out["status"])
	}
	if out["install_token"] == "" {
		t.Fatalf("expected install token in response")
	}
}

func TestInstallSessionApprovalHandlerTransition(t *testing.T) {
	handler, store := newTestHandler(t)

	created, _, err := store.CreateInstallSession(requests.CreateInstallInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/install-sessions/"+created.ID+"/approval", strings.NewReader(`{"approved":true}`))
	rr := httptest.NewRecorder()
	handler.InstallSessionApproval(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"approved"`) {
		t.Fatalf("expected approved status in body, got %s", rr.Body.String())
	}
}

func TestRedeemInstallTokenHandlerConsumesToken(t *testing.T) {
	handler, store := newTestHandler(t)

	created, token, err := store.CreateInstallSession(requests.CreateInstallInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	_, err = store.SetInstallApproval(created.ID, true)
	if err != nil {
		t.Fatalf("unexpected approval error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/install-sessions/redeem", strings.NewReader(`{"token":"`+token+`"}`))
	rr := httptest.NewRecorder()
	handler.RedeemInstallToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/install-sessions/redeem", strings.NewReader(`{"token":"`+token+`"}`))
	rr2 := httptest.NewRecorder()
	handler.RedeemInstallToken(rr2, req2)
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("expected status 404 for consumed token, got %d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestInstallSessionResultHandlerInstalledTransition(t *testing.T) {
	handler, store := newTestHandler(t)

	created, _, err := store.CreateInstallSession(requests.CreateInstallInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	_, err = store.SetInstallApproval(created.ID, true)
	if err != nil {
		t.Fatalf("unexpected approval error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/install-sessions/"+created.ID+"/result", strings.NewReader(`{"status":"installed"}`))
	rr := httptest.NewRecorder()
	handler.InstallSessionResult(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"installed"`) {
		t.Fatalf("expected installed status in body, got %s", rr.Body.String())
	}
}

func TestGetInstallSessionStatus(t *testing.T) {
	handler, store := newTestHandler(t)

	created, _, err := store.CreateInstallSession(requests.CreateInstallInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/install-sessions/"+created.ID, nil)
	rr := httptest.NewRecorder()
	handler.GetInstallSession(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"id":"`+created.ID+`"`) {
		t.Fatalf("expected session id in body, got %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"requested"`) {
		t.Fatalf("expected requested status in body, got %s", rr.Body.String())
	}
}

func TestGetInstallSessionStatusNotFound(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/install-sessions/missing", nil)
	rr := httptest.NewRecorder()
	handler.GetInstallSession(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d body=%s", rr.Code, rr.Body.String())
	}
}
