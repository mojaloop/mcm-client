# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🎯 Start Here

**ALWAYS read this file first when starting work on this project:**

→ **[`_cc/docs/01-overview.md`](./_cc/docs/01-overview.md)** - Complete project overview (master reference)

This single file contains everything needed to understand the project:
- Architecture overview and tech stack
- Critical entry points and code flows
- Common operations (run, test, deploy)
- Key gotchas and warnings
- Links to all detailed documentation

**For quick code navigation:**
→ [`_cc/docs/12-ai-guide.md`](./_cc/docs/12-ai-guide.md) - Entry points, call chains, side effects

## Project Overview

`@pm4ml/mcm-client` is a TypeScript library for the Payment Manager for Mojaloop (PM4ML) Connection Manager Client. It manages automated certificate lifecycle, configuration synchronization, and secure communication with the Mojaloop Hub using HashiCorp Vault and XState state machines.

## Architecture

### XState Parallel State Machine

The core of this library is `ConnectionStateMachine` (src/lib/stateMachine/ConnectionStateMachine.ts), which orchestrates 11 parallel workflows using XState v4:

1. **fetchingHubCA**: Retrieve Hub Certificate Authority
2. **creatingDFSPCA**: Generate DFSP Certificate Authority
3. **creatingDfspClientCert**: Create DFSP client certificate for Hub authentication
4. **creatingDfspServerCert**: Create DFSP server certificate for incoming connections
5. **creatingHubClientCert**: Sign Hub's CSR with DFSP CA
6. **pullingPeerJWS**: Fetch peer JWS public keys
7. **uploadingPeerJWS**: Upload DFSP JWS public keys
8. **creatingJWS**: Generate JWS key pairs
9. **endpointConfig**: Configure endpoint settings
10. **connectorConfig**: Configure connector settings
11. **progressMonitor**: Track and report state of all workflows

#### State Persistence
- State machine state is persisted to Vault at `state-machine-state` **only on external events** (not intermediate XState events)
- External events defined in `src/lib/stateMachine/constants.ts` (8 defaults: PEER_JWS_CONFIGURED, DFSP_JWS_PROPAGATED, DFSP_CA_PROPAGATED, DFSP_SERVER_CERT_CONFIGURED, DFSP_CLIENT_CERT_CONFIGURED, HUB_CLIENT_CERT_SIGNED, ENDPOINT_CONFIG_PROPAGATED, UPLOADING_DFSP_CSR)
- Additional external events can be configured via `ADDITIONAL_EXTERNAL_EVENT_TYPES_CSV` environment variable
- Each machine version has a SHA-256 hash of its state configuration
- On restart, the machine checks hash and version to decide whether to restore or start fresh
- Actions (pending timers/invocations) are serialized and restored

### Vault Integration

`Vault` class (src/lib/vault/index.ts) wraps `node-vault` and provides:

#### Authentication
- Kubernetes JWT authentication (`auth.k8s`)
- AppRole authentication (`auth.appRole`)
- Automatic token refresh before expiration

#### PKI Operations
- `createCA()`: Generate root CA with configurable subject
- `createDFSPServerCert()`: Issue server certificates with SAN extensions
- `signHubCSR()`: Sign Hub's CSR using client role
- `setDFSPCaCertChain()`: Configure Vault with DFSP CA bundle

#### Token Refresh Pattern
All Vault operations are wrapped with `_withTokenRefresh()`:
- Catches 403 errors indicating expired/invalid tokens
- Automatically reconnects and retries once on token expiration
- Uses configurable retry delay (`retryDelayMs`)

### WebSocket Control Server

The Control Server (src/lib/ControlServer/Server.ts) provides a WebSocket API for real-time updates:

#### Protocol Messages
- `CONFIGURATION.READ`: Request current configuration
- `CONFIGURATION.NOTIFY`: Broadcast configuration changes
- `PEER_JWS.READ`: Request peer JWS keys
- `PEER_JWS.NOTIFY`: Upload/broadcast peer JWS changes

#### Health Management
- Heartbeat every 30 seconds via WebSocket ping/pong
- Terminates unresponsive clients
- Health check endpoint reports server and client status

#### Internal Events
Uses EventEmitter pattern to decouple state machine from control server:
- `SERVER.BROADCAST_CONFIG_CHANGE`: Notify all clients of config updates
- `SERVER.BROADCAST_PEER_JWS_CHANGE`: Notify all clients of JWS key changes

### State Machine States

Each state module in `src/lib/stateMachine/states/` exports:
- `Context`: Type for state-specific context data
- `Event`: Union type of events the state handles
- `createState<Context>()`: Factory function returning XState state config
- `createGuards<Context>()`: Conditional logic for transitions
- `createActions<Context>()`: Side effects (optional)

States use the `MachineOpts` interface for dependency injection:
- `logger`: SDK logger instance
- `vault`: Vault client for PKI operations
- `dfspCertificateModel`: API client for DFSP certificate endpoints
- `dfspEndpointModel`: API client for DFSP endpoint configuration
- `hubCertificateModel`: API client for Hub certificate endpoints
- `hubEndpointModel`: API client for Hub endpoint configuration
- `refreshIntervalSeconds`: Polling interval for state refresh
- `certExpiryThresholdDays`: Days before expiry to trigger renewal

### Certificate Lifecycle

Certificate states implement the following pattern:
1. Check if certificate exists and is valid (not expired, within threshold)
2. If missing/expiring:
   - Generate CSR with `vault.createCSR()`
   - Sign CSR via appropriate Vault method
   - Upload certificate to MCM API
3. Schedule next check using `refreshIntervalSeconds`
4. Transition to success/error states

DFSP server certificates support Subject Alternative Names (SANs) for DNS and IP addresses.

### Testing

#### Unit Tests
- Located in `src/test/unit/model/stateMachine/`
- Run against compiled code in `dist/test/unit`
- Use `jest` with `mockdate` and `nock` for mocking
- Coverage threshold: 50% (statements, branches, functions, lines)

#### Integration Tests
- Located in `src/test/integration/`
- Run with `npm run test:int`
- Require live environment (Vault, MCM API)

#### Common Mocks
`src/test/unit/model/stateMachine/commonMocks.ts` provides shared test fixtures for state machine testing.

## Development Commands

### Build and Test
```bash
npm run build              # Compile TypeScript to dist/
npm test                   # Run unit tests from dist/test/unit
npm run test:int           # Run integration tests (requires environment)
```

### Code Quality
```bash
npm run lint               # Check code style with ESLint
npm run lint:fix           # Auto-fix linting issues
```

### Dependencies
```bash
npm run dep:check          # Check for outdated dependencies
npm run dep:update         # Update dependencies
```

### Pre-commit Hooks
Husky runs `lint`, `build`, and `test` before each commit.

## TypeScript Configuration

- **Target**: ES2020
- **Module**: CommonJS
- **Paths**: `@app/*` maps to `src/*`
- **Strict Mode**: Enabled (except `noImplicitAny`)
- **Output**: `dist/` directory

## Key Dependencies

- `xstate@4.35.4`: State machine implementation (v4 API)
- `@xstate/inspect`: State machine visualization at https://stately.ai/viz
- `node-vault`: HashiCorp Vault client
- `node-forge`: PKI operations (CSR, keys, certificates)
- `@mojaloop/sdk-standard-components`: Logging and utilities
- `ws`: WebSocket server and client

## Docker

The project includes:
- `Dockerfile`: Multi-stage build for production image
- `docker-compose.yaml`: Local development with MySQL database

## Important Notes

- State machine introspection can be enabled via `stateMachineInspectEnabled` config
- Vault token lease duration determines reconnection schedule (max 2^31/2-1 ms)
- The library is published as an npm package with only `dist/` included
- No README.md exists in the repository
