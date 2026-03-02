package openclaw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"enclout/services/control-plane/internal/requests"
)

type fakeStore struct {
	lastCreateAccessInput   requests.CreateInput
	lastCreateInstallInput  requests.CreateInstallInput
	lastInstallApprovalID   string
	lastInstallApprovalFlag bool
	lastInstallResultID     string
	lastInstallResultStatus requests.InstallStatus
	lastInstallResultReason string
}

func (s *fakeStore) Create(in requests.CreateInput) (requests.ConnectionRequest, error) {
	s.lastCreateAccessInput = in
	return requests.ConnectionRequest{
		ID:             "req_1",
		OpenClawUserID: in.OpenClawUserID,
		DeviceID:       in.DeviceID,
		ConnectorID:    in.ConnectorID,
		SourceChannel:  in.SourceChannel,
		Status:         requests.StatusPendingLocalConfirm,
		Nonce:          "nonce",
	}, nil
}

func (s *fakeStore) CreateInstallSession(in requests.CreateInstallInput) (requests.InstallSession, string, error) {
	s.lastCreateInstallInput = in
	return requests.InstallSession{
		ID:             "ins_1",
		OpenClawUserID: in.OpenClawUserID,
		DeviceID:       in.DeviceID,
		ConnectorID:    in.ConnectorID,
		SourceChannel:  in.SourceChannel,
		Status:         requests.InstallStatusRequested,
		CreatedAt:      time.Date(2026, 2, 24, 17, 0, 0, 0, time.UTC),
		ExpiresAt:      time.Date(2026, 2, 24, 17, 5, 0, 0, time.UTC),
	}, "tok_1", nil
}

func (s *fakeStore) SetInstallApproval(id string, approved bool) (requests.InstallSession, error) {
	s.lastInstallApprovalID = id
	s.lastInstallApprovalFlag = approved
	return requests.InstallSession{
		ID:     id,
		Status: requests.InstallStatusApproved,
	}, nil
}

func (s *fakeStore) SetInstallResult(id string, status requests.InstallStatus, reasonCode string) (requests.InstallSession, error) {
	s.lastInstallResultID = id
	s.lastInstallResultStatus = status
	s.lastInstallResultReason = reasonCode
	return requests.InstallSession{
		ID:         id,
		Status:     status,
		ReasonCode: reasonCode,
	}, nil
}

func TestIntentMapsToCreateRequest(t *testing.T) {
	store := &fakeStore{}
	handler := NewIntentHandler(store)

	body := `{"intent":"request_connector_access","openclaw_user_id":"usr_1","connector_id":"conn_1","device_id":"dev_1","source_channel":"telegram"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/openclaw/intents", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d body=%s", rr.Code, rr.Body.String())
	}
	if store.lastCreateAccessInput.SourceChannel != "telegram" {
		t.Fatalf("expected source channel metadata to be stored")
	}
}

func TestIntentMapsToCreateInstallSession(t *testing.T) {
	store := &fakeStore{}
	handler := NewIntentHandler(store)

	body := `{"intent":"request_connector_install","openclaw_user_id":"usr_1","connector_id":"conn_1","device_id":"dev_1","source_channel":"telegram"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/openclaw/intents", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unexpected json response: %v", err)
	}
	if out["install_token"] != "tok_1" {
		t.Fatalf("expected install token in body, got %v", out["install_token"])
	}
	if out["install_session_id"] != "ins_1" {
		t.Fatalf("expected install_session_id in body, got %v", out["install_session_id"])
	}
	if out["expires_at"] == "" {
		t.Fatalf("expected expires_at in body")
	}
	commands, ok := out["install_commands"].(map[string]any)
	if !ok {
		t.Fatalf("expected install_commands object in body")
	}
	if !strings.Contains(commands["darwin"].(string), "enclout install") {
		t.Fatalf("expected darwin command template, got %v", commands["darwin"])
	}
	if !strings.Contains(commands["linux"].(string), "enclout install") {
		t.Fatalf("expected linux command template, got %v", commands["linux"])
	}
	if store.lastCreateInstallInput.SourceChannel != "telegram" {
		t.Fatalf("expected source channel metadata to be stored")
	}
}

func TestIntentMapsToInstallApproval(t *testing.T) {
	store := &fakeStore{}
	handler := NewIntentHandler(store)

	body := `{"intent":"approve_install_session","install_session_id":"ins_1","approved":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/openclaw/intents", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if store.lastInstallApprovalID != "ins_1" || !store.lastInstallApprovalFlag {
		t.Fatalf("expected approval mapping, got id=%q approved=%v", store.lastInstallApprovalID, store.lastInstallApprovalFlag)
	}
}

func TestIntentMapsToInstallResult(t *testing.T) {
	store := &fakeStore{}
	handler := NewIntentHandler(store)

	body := `{"intent":"install_session_result","install_session_id":"ins_1","status":"failed","reason_code":"LaunchdInstallError"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/openclaw/intents", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if store.lastInstallResultID != "ins_1" {
		t.Fatalf("expected result id mapping, got %q", store.lastInstallResultID)
	}
	if store.lastInstallResultStatus != requests.InstallStatusFailed {
		t.Fatalf("expected failed status mapping, got %q", store.lastInstallResultStatus)
	}
	if store.lastInstallResultReason != "LaunchdInstallError" {
		t.Fatalf("expected reason mapping, got %q", store.lastInstallResultReason)
	}
}
