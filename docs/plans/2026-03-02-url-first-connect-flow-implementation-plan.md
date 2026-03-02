# URL-First Connect Flow Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let users request connection first, receive a clickable install URL, install `enclout`, and then let the connector provide `connector_id`/`device_id` back for final access request.

**Architecture:** Extend install sessions to support "pending identity binding" and add a registration step where installer/runtime reports discovered `connector_id` and `device_id`. Add a new OpenClaw intent for URL-first connect and a public install URL target that carries the one-time token. Update local installer to register IDs before marking install complete.

**Tech Stack:** Go 1.26 services (`net/http`, `httptest`), existing control-plane store/handler/openclaw packages, existing local-agent install client/runner, markdown docs + skill templates.

---

## Tracking

- [x] Task 1: Add failing tests for URL-first connect intent + install URL response
- [x] Task 2: Add failing tests for install session identity registration endpoint
- [x] Task 3: Implement control-plane state/store/handler changes
- [x] Task 4: Implement local-agent installer registration call
- [x] Task 5: Update skill contract/docs for URL-first UX
- [x] Task 6: Run verification and push

### Task 1: Add failing tests for URL-first connect intent + install URL response

**Files:**
- Modify: `services/control-plane/internal/openclaw/intent_handler_test.go`

**Steps:**
1. Add test `TestIntentRequestConnectorConnectReturnsInstallURL`.
2. Assert intent `request_connector_connect` returns `201`.
3. Assert response includes:
   - `install_session_id`
   - `install_token`
   - `install_url`
   - `status` (`requested`)
4. Run: `cd services/control-plane && go test ./internal/openclaw -run TestIntentRequestConnectorConnectReturnsInstallURL -v`
5. Confirm fail before implementation.

### Task 2: Add failing tests for install session identity registration endpoint

**Files:**
- Modify: `services/control-plane/internal/http/install_session_handler_test.go`
- Modify: `services/control-plane/internal/http/install_session_flow_test.go`

**Steps:**
1. Add handler test for `POST /v1/install-sessions/{id}/registration`.
2. Assert registration updates `connector_id` + `device_id`.
3. Extend flow test to verify URL-first path:
   - create session via new intent
   - approve
   - register IDs
   - poll shows bound IDs
4. Run targeted tests and confirm fail.

### Task 3: Implement control-plane state/store/handler changes

**Files:**
- Modify: `services/control-plane/internal/requests/model.go`
- Modify: `services/control-plane/internal/requests/store.go`
- Modify: `services/control-plane/internal/requests/file_store.go`
- Modify: `services/control-plane/internal/http/handler.go`
- Modify: `services/control-plane/internal/http/install_session_handler.go`
- Modify: `services/control-plane/internal/openclaw/intent_handler.go`
- Modify: `services/control-plane/cmd/api/main.go`

**Steps:**
1. Add store method for install identity binding (`SetInstallIdentity`).
2. Allow URL-first install-session creation without pre-supplied `connector_id`/`device_id`.
3. Add HTTP endpoint `POST /v1/install-sessions/{id}/registration`.
4. Add new intent `request_connector_connect`.
5. Add `install_url` in intent response.
6. Add public install landing route (`/install?...`) to support clickable UX.
7. Run relevant tests until green.

### Task 4: Implement local-agent installer registration call

**Files:**
- Modify: `services/local-agent/internal/api/client.go`
- Modify: `services/local-agent/internal/api/client_test.go`
- Modify: `services/local-agent/internal/install/runner.go`
- Modify: `services/local-agent/internal/install/runner_test.go`
- Modify: `services/local-agent/cmd/install/main.go`
- Modify: `services/local-agent/cmd/install/main_test.go`

**Steps:**
1. Add installer API method to post registration to control plane.
2. Add flags/env support for discovering/providing `connector_id` + `device_id`.
3. Register identities before install result post.
4. Keep current path backward-compatible when IDs are already present.
5. Run targeted local-agent tests.

### Task 5: Update skill contract/docs for URL-first UX

**Files:**
- Modify: `skills/enclout-openclaw-agent/SKILL.md`
- Modify: `docs/runbooks/openclaw-skill-contract.md`
- Modify: `docs/runbooks/connector-access-flow.md`
- Modify: `README.md`

**Steps:**
1. Change user flow to: request connect -> receive URL -> install -> auto-bind IDs -> access.
2. Ensure skill never asks user for runtime secrets or IDs upfront.
3. Add clear expected chat behavior and failure handling.

### Task 6: Run verification and push

**Steps:**
1. Run targeted packages first:
   - `cd services/control-plane && go test ./internal/openclaw ./internal/http ./internal/requests -v`
   - `cd services/local-agent && go test ./cmd/install ./internal/install ./internal/api -v`
2. Run full gate:
   - `bash scripts/verify-m1.sh`
3. Commit with focused message.
4. Push `main` to `origin/main`.
