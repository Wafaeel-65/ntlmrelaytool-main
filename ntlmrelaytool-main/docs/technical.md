# NTLM Relay Tool – Technical Documentation

## Table of Contents
1. [Overview](#overview)  
2. [Architecture](#architecture)  
3. [Module Breakdown](#module-breakdown)  
   3.1 [Capture Module](#capture-module)  
   3.2 [Exploit Module](#exploit-module)  
   3.3 [Storage Module](#storage-module)  
   3.4 [Utilities](#utilities)  
4. [Command-Line Interface](#command-line-interface)  
5. [Configuration Files](#configuration-files)  
6. [Logging](#logging)  
7. [Database Schema](#database-schema)  
8. [Testing](#testing)  
9. [Extensibility & Hooks](#extensibility--hooks)  

---

## 1. Overview  
This document describes the internal design and implementation details of the NTLM Relay Tool. It is intended for developers and maintainers who wish to understand, extend, or troubleshoot the codebase.

## 2. Architecture  
```text
    ┌─────────────────┐     ┌───────────────┐     ┌──────────────┐
    │ Network Capture │──►  │  Parser       │──►  │  Relay       │
    │ (Scapy / pcap)  │     │ (extract data)│     │ (SMB/LDAP/   │
    │                 │     └───────────────┘     │  HTTP)       │
    └─────────────────┘           │               └──────────────┘
                                  ▼
                             ┌─────────┐
                             │ Storage │
                             │ (Mongo) │
                             └─────────┘
```

- **Capture**: Listens on raw sockets, decodes LLMNR/NBT-NS/mDNS and SMB/HTTP packets.  
- **Parser**: Identifies NTLM message types, extracts credentials and hashes.  
- **Relay**: Implements protocol-specific negotiation (SMB, LDAP, HTTP).  
- **Storage**: Persists events and results in MongoDB.  

## 3. Module Breakdown

### 3.1 Capture Module  
**Location**: `src/modules/capture/`

- **parser.py**  
  - `class NTLMParser.extract_ntlm_info(payload)`  
    • Detect NTLM signature, parse Type 1/2/3 messages  
    • Extract `username`, `domain`, `challenge`, `response`  
- **responder.py**  
  - LLMNR/NBT-NS/mDNS poisoning listeners on UDP 137, 5355, 5353  
  - Replies with attacker IP to force NTLM auth  
- **packet_sniffer.py**  
  - Uses Scapy’s `sniff()` with BPF filters  
  - Callback dispatch to parser and responder  

### 3.2 Exploit Module  
**Location**: `src/modules/exploit/`

- **relay.py**  
  - `class SMBRelayClient` & `LDAPRelayClient` & `HTTPRelayClient`  
  - Flow: receive Type 1 → forward to target → relay Type 2 back → forward Type 3  
- **ntlmrelayserver.py**  
  - Implements SMB server endpoints for NTLM challenge/response  
- **cracker.py**  
  - Integrates Passlib/PyCryptodome  
  - Supports wordlist, brute-force, hybrid attacks  

### 3.3 Storage Module  
**Location**: `src/modules/storage/`

- **database.py**  
  - Manages `MongoClient` pool, handles retries  
- **models.py**  
  - Defines Pydantic-style schemas for:
    - `AuthenticationAttempt`
    - `RelayResult`
    - `CrackedCredential`

### 3.4 Utilities  
**Location**: `src/utils/`

- **config.py**  
  - Loads `config/*.ini` via `ConfigParser`  
  - Environment variable overrides  
- **mongo_handler.py**  
  - Wraps CRUD operations, index creation  
- **hash_handler.py**  
  - NTLM hash computation & verification  
- **logger.py**  
  - Configures Python `logging` module per `logging.ini`  

## 4. Command-Line Interface  
**Entry Point**: `src/main.py` (uses `argparse`)

```bash
usage: main.py <command> [options]

Commands:
  poison   --interface IFACE [--protocols llmnr,nbtns,mdns] [--debug]
  relay    --interface IFACE --target TARGET_URL        [--debug]
  attack   --interface IFACE --target TARGET_URL [--crack wordlist] [--debug]
  list     [--type auth|relay] [--status success|fail] [--format json|table]
  report   [--format html|md] --output FILE
  export   [--format json|csv] --output FILE [--filter ...]
```

Each subcommand instantiates the corresponding module classes and invokes high-level methods:
- `Controller.poison()`
- `Controller.relay()`
- `Controller.attack()`
- etc.

## 5. Configuration Files  
- **config/mongodb.ini**  
  ```ini
  [mongodb]
  host = localhost
  port = 27017
  database = ntlm_relay
  username =
  password =
  auth_source = admin
  connection_timeout = 5000
  retry_writes = true
  ```
- **config/logging.ini**  
  ```ini
  [loggers]
  keys = root, capture, exploit, storage

  [handlers]
  keys = consoleHandler, fileHandler

  [formatters]
  keys = standard

  [logger_root]
  level = INFO
  handlers = consoleHandler, fileHandler

  [handler_fileHandler]
  class = handlers.RotatingFileHandler
  level = DEBUG
  formatter = standard
  args = ('app.log','a',10485760,5)
  ```

## 6. Logging  
- **Levels**: DEBUG, INFO, WARNING, ERROR  
- **Handlers**: Console, Rotating file (`app.log`), Audit (`audit.log`)  
- **Component-specific** logs via `"capture"`, `"exploit"`, `"storage"` loggers  

## 7. Database Schema  

**AuthenticationAttempt**  
```jsonc
{
  "_id": ObjectId,
  "timestamp": ISODate,
  "src_ip": "192.168.1.50",
  "username": "alice",
  "domain": "CORP",
  "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
  "protocol": "SMB",
  "status": "Captured"
}
```

**RelayResult**  
```jsonc
{
  "_id": ObjectId,
  "auth_id": ObjectId,
  "target": "192.168.1.100",
  "protocol": "SMB",
  "success": true,
  "operations": ["list_shares"],
  "error": null,
  "timestamp": ISODate
}
```

## 8. Testing  
- **Unit tests** in `tests/unit/`  
- **Integration tests** in `tests/integration/`  
- **Performance tests** in `tests/performance/`  
- Run all tests:
  ```bash
  pytest --cov=src --cov-report=term-missing
  ```
- Fixtures in `tests/fixtures/` (pcap files, JSON mocks)

## 9. Extensibility & Hooks  
- **Custom Responders**: Implement new poisoning protocols in `responder.py`  
- **New Relay Targets**: Subclass `BaseRelayClient` in `exploit/relay.py`  
- **Event Hooks**:  
  ```python
  from utils.logger import get_logger
  logger = get_logger('capture')
  logger.info("Custom hook called", extra={'hook': 'on_packet'})
  ```
- **Configuration**: Extend `config.ini` and handle in `config.py`

---
**Last Updated**: May 2025  
**Review Status**: Technical Review Complete