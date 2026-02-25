package openclaw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"enclout/services/control-plane/internal/requests"
)

type fakeStore struct {
	last requests.CreateInput
}

func (s *fakeStore) Create(in requests.CreateInput) (requests.ConnectionRequest, error) {
	s.last = in
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
	if store.last.SourceChannel != "telegram" {
		t.Fatalf("expected source channel metadata to be stored")
	}
}
