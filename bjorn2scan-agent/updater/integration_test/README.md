# Updater Integration Test

This directory contains Docker-based integration tests for the agent auto-update system.

## Overview

The test simulates a complete update lifecycle using mock servers:
- Mock Atom feed server (serves release feed)
- Mock asset server (serves binary tarballs and checksums)
- Test agent binary that can simulate successful and failed updates

## Test Scenarios

1. **Successful Upgrade**: Agent upgrades from v0.1.0 to v0.1.1, health check passes, update commits
2. **Failed Health Check**: Agent upgrades but health check fails, triggers automatic rollback

## Running Tests

```bash
cd bjorn2scan-agent/updater/integration_test
./run_test.sh
```

## Test Architecture

```
┌─────────────┐
│  Mock Feed  │  Serves Atom feed with release info
│   Server    │  (port 8080)
└─────────────┘
       │
       ├─────┐
       │     │
       v     v
┌─────────────┐
│  Mock Asset │  Serves binary tarballs & checksums
│   Server    │  (port 8081)
└─────────────┘
       │
       v
┌─────────────┐
│ Test Agent  │  bjorn2scan-agent with mocked config
│  Container  │  Points to mock servers
└─────────────┘
```

## Files

- `Dockerfile` - Test environment setup
- `run_test.sh` - Main test runner
- `mock-server.go` - Mock feed and asset servers
- `test-scenarios.sh` - Test scenario definitions
