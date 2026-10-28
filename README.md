# Authorization Gateway

A security-focused authorization gateway built with **FastAPI and PyJWT**, demonstrating practical API security engineering across authentication, authorization, multi-tenant isolation, security testing, and DevSecOps automation.

> **Portfolio project:** designed to demonstrate security architecture, implementation, and verification practices. It is not presented as a production-ready authorization platform.

## Quick start

Requirements: Python 3.11 and, optionally, Docker for containerized execution.

On Windows PowerShell, create and activate a virtual environment, then install the development dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

Start the API in development mode:

```powershell
uvicorn app.main:app --reload
```

Run the verification checks:

```powershell
python -m ruff check .
python -m mypy app
python -m pytest -v
python -m bandit -r app -q
python -m pip_audit -r requirements.txt
```

The CI workflow also builds the Docker image. These commands are documented entry points; run them locally to confirm the current environment passes.

---

## What this project demonstrates

The project implements a centralized authorization layer for a multi-tenant API.

It demonstrates how to enforce security boundaries between:

* **Authentication** — establishing who the caller is.
* **Authorization** — determining what the caller is allowed to do.
* **Tenant isolation** — preventing access across tenant boundaries.
* **Ownership** — allowing resource owners to perform explicitly permitted actions.
* **RBAC** — controlling privileged operations through roles.
* **Scopes** — restricting permissions to specific capabilities.
* **Security testing** — testing authorization failures as deliberately as successful requests.
* **DevSecOps** — continuously checking code quality and security in CI.

The central architectural principle is:

> **A valid identity does not automatically imply permission to access a resource.**

---

## Security Architecture

```text
                         ┌─────────────────────┐
                         │      Client/API     │
                         └──────────┬──────────┘
                                    │
                              Bearer JWT
                                    │
                                    ▼
                    ┌────────────────────────────┐
                    │   Authorization Gateway    │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │    Token Verification      │
                    │                            │
                    │ JWT / JWKS                 │
                    │ Algorithm allowlist        │
                    │ Issuer / Audience           │
                    │ exp / nbf / iat             │
                    │ Signature verification     │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │     Identity Context       │
                    │                            │
                    │ Subject                    │
                    │ Tenant                     │
                    │ Roles                      │
                    │ Scopes                     │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │       Policy Engine        │
                    │                            │
                    │ Tenant isolation           │
                    │ Ownership                  │
                    │ Role + scope               │
                    │ Fail-closed evaluation     │
                    └─────────────┬──────────────┘
                                  │
                         ┌────────┴────────┐
                         │                 │
                       ALLOW              DENY
                         │                 │
                         ▼                 ▼
                  Business logic       HTTP error
                         │
                         ▼
                 Structured audit
```

Authorization decisions are centralized in `PolicyEngine.evaluate()` rather than being independently implemented inside each endpoint.

---

## Threat Model

The project focuses on authorization failures that can occur even when authentication is correctly implemented.

### BOLA — Broken Object Level Authorization

A user may possess a valid token but attempt to access another user's resource.

Example:

```text
user-a2 → vault-a1
```

The resource belongs to `user-a1`, so ownership-based access must not be granted simply because both users belong to the same tenant.

---

### BFLA — Broken Function Level Authorization

A user may have access to a resource without being authorized to perform a privileged operation on it.

For example:

```text
user-a1 → DELETE vault-a1
```

Ownership alone does not grant the `vault.delete` capability.

The policy requires the appropriate administrative role and scope.

---

### Cross-Tenant Access

A valid user from one tenant must not access resources belonging to another tenant.

```text
tenant-b → tenant-a resource
```

Tenant isolation is evaluated **before** the policy table.

This makes tenant boundaries a structural authorization invariant rather than an optional endpoint-level check.

---

### Authorization Enumeration

The API avoids exposing whether a resource exists in another tenant.

Cross-tenant access and nonexistent resources are intentionally mapped to the same external `404` response.

This reduces the ability to use the API as a resource-existence oracle.

---

## Authorization Model

The authorization decision is based on multiple security dimensions, with ownership as an explicit alternative path for selected actions:

```text
Identity
   │
   ├── Tenant boundary
   │
   ├── Resource ownership
   │
   ├── Role
   │
   └── Scope
        │
        ▼
   Policy Engine
        │
     ALLOW / DENY
```

The policy table currently defines:

| Action                   | Owner access | Alternative privileged access |
| ------------------------ | ------------ | ----------------------------- |
| `vault.read`             | Allowed      | `admin` role + `vault:read` scope |
| `vault.update`           | Allowed      | `admin` role + `vault:write` scope |
| `vault.delete`           | Not allowed  | `admin` role + `vault:delete` scope |
| `vault.share`            | Allowed      | `admin` role + `vault:share` scope |
| `vault.admin`            | Not allowed  | `admin` role + `vault:admin` scope |
| `admin.resources.create` | Not allowed  | `admin` role + `admin:write` scope |
| `admin.audit.read`       | Not allowed  | `admin` role + `admin:read` scope |

For actions marked **Allowed**, ownership is an independent authorization path: the owner can be allowed without satisfying the alternative role-and-scope requirements. Tenant isolation is still checked first.

Ownership and administrative permissions are therefore treated as separate authorization mechanisms.

---

## Fail-Closed Authorization

Unknown actions do not receive implicit permission.

The authorization engine follows this general evaluation order:

```text
Unknown action?
    └── DENY

Different tenant?
    └── DENY

Owner and action allows ownership?
    └── ALLOW

Required role + scope satisfied?
    └── ALLOW

Otherwise
    └── DENY
```

This makes the absence of an explicit authorization rule a denial rather than an accidental permission.

---

## JWT Security

JWT validation is centralized in a single verification boundary.

The implementation validates:

* JWT signature
* server-controlled algorithm allowlist
* `kid`
* issuer (`iss`)
* audience (`aud`)
* expiration (`exp`)
* not-before (`nbf`)
* issued-at (`iat`)
* required claims
* subject (`sub`)
* tenant identity
* role types
* scope types

The application does not trust the algorithm declared by an incoming token to determine which verification algorithm should be accepted.

---

## JWKS and Key Management

The project separates development and production-oriented key providers.

### Development

A local RSA key pair can be generated for the demonstration environment.

Development keys are stored outside the tracked source tree and are intentionally excluded from version control.

### Production-oriented provider

The production provider uses JWKS-based key resolution through PyJWT's `PyJWKClient`, including key caching and bounded configuration.

The repository does **not** contain private signing keys or real credentials.

---

## Audit Logging

Authorization activity is represented through structured audit events.

Audit records are designed around identifiers and security decisions rather than sensitive credential material.

The audit layer explicitly avoids receiving or logging:

* raw JWTs
* `Authorization` headers
* passwords
* private keys
* refresh tokens

The project also provides tenant-scoped administrative audit access.

---

## Security Test Matrix

The authorization matrix is represented as executable tests rather than documentation alone.

Representative scenarios include:

| Scenario                                       | Expected Result |
| ---------------------------------------------- | --------------: |
| Owner reads own vault                          |           `200` |
| Owner attempts delete without admin permission |           `403` |
| Same-tenant user accesses another user's vault |           `403` |
| Admin reads tenant resource                    |           `200` |
| Admin deletes authorized resource              |           `204` |
| Cross-tenant resource access                   |           `404` |
| Non-admin accesses admin endpoint              |           `403` |
| Request without token                          |           `401` |

The security tests specifically exercise negative authorization paths, including BOLA, BFLA, tenant isolation, and privilege-boundary failures.

---

## DevSecOps Pipeline

The repository includes a GitHub Actions security gate covering:

```text
Ruff
  ↓
Mypy
  ↓
Pytest
  ↓
Bandit
  ↓
pip-audit
  ↓
Docker build
```

The workflow runs these checks automatically for pushes to `main` and pull requests targeting `main`.

The goal is to make security verification part of the development workflow rather than an isolated manual activity.

### Local verification

The equivalent checks can be executed locally with the project's configured development dependencies:

```powershell
python -m ruff check .
python -m mypy app
python -m pytest -v
python -m bandit -r app -q
python -m pip_audit -r requirements.txt
docker build -t authorization-gateway:ci .
```

---

## Project Structure

```text
authorization-gateway/
│
├── app/
│   ├── api/
│   │   ├── deps.py
│   │   ├── vault.py
│   │   └── admin.py
│   │
│   ├── security/
│   │   ├── authentication/
│   │   │   ├── keys.py
│   │   │   ├── jwks.py
│   │   │   └── jwt.py
│   │   │
│   │   ├── authorization/
│   │   │   ├── context.py
│   │   │   ├── decision.py
│   │   │   ├── engine.py
│   │   │   └── policy.py
│   │   │
│   │   └── audit/
│   │       └── events.py
│   │
│   ├── data/
│   │   └── store.py
│   │
│   ├── config.py
│   ├── models.py
│   └── main.py
│
├── scripts/
│   └── issue_token.py
│
├── tests/
│   ├── security/
│   ├── unit/
│   └── integration/
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── pytest.ini
├── requirements.txt
└── requirements-dev.txt
```

---

## Running Locally

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

The application supports a development configuration with locally generated development keys.

Run the API with:

```powershell
uvicorn app.main:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

The project also includes Docker and Docker Compose configuration for containerized execution.

---

## Security Boundaries

Several security decisions are deliberately centralized.

### Authentication boundary

`app/security/authentication/jwt.py`

Responsible for establishing whether a token can be trusted.

### Authorization boundary

`app/security/authorization/engine.py`

Responsible for deciding whether an authenticated identity can perform a specific action.

### Policy definition

`app/security/authorization/policy.py`

Contains declarative authorization rules.

### Tenant boundary

Evaluated before the authorization policy so that a resource from another tenant cannot become authorized through ownership, role, or scope.

### Audit boundary

`app/security/audit/events.py`

Receives security-relevant identifiers and decisions without handling raw credentials.

---

## Design Principles

The project is intentionally built around several security engineering principles:

* **Authenticate once, authorize explicitly.**
* **Never equate a valid JWT with permission.**
* **Enforce tenant isolation before resource-level policy.**
* **Centralize authorization decisions.**
* **Fail closed when policy is missing or ambiguous.**
* **Test denial paths, not only successful requests.**
* **Keep sensitive credentials outside source control.**
* **Automate security checks in CI.**
* **Prefer explicit security invariants over scattered endpoint checks.**

---

## Scope and Limitations

This project deliberately focuses on authorization engineering rather than attempting to reproduce an entire production identity platform.

Current limitations include:

* in-memory demonstration data store
* no production database transaction model
* no database-level Row-Level Security
* no cloud IAM integration
* no Kubernetes deployment
* no distributed policy service
* no production-grade observability stack
* no claim that the implementation has been battle-tested at production scale

These limitations are intentional and define the scope of the portfolio demonstration.

---

## Security Hygiene

The repository is designed so that local development material does not become part of the public source tree.

The following are excluded from version control:

```text
.env
.devkeys/
.venv/
*.pyc
__pycache__/
*.egg-info/
```



No real credentials, private signing keys, API keys, or production secrets should be committed to this repository.

---

## Project Objective

This repository is a practical demonstration of **Cloud Security / DevSecOps engineering** applied to API authorization.

The emphasis is not on building a large application. It is on demonstrating the engineering process:

```text
Threat
  ↓
Security invariant
  ↓
Architectural boundary
  ↓
Security control
  ↓
Adversarial test
  ↓
Automated verification
  ↓
CI security gate
```

The result is a compact security-focused system where authorization decisions, security controls, tests, and DevSecOps verification are connected rather than implemented as isolated features.

---

## Status

**Milestone 1 — Authorization Core:** Complete

**Milestone 2 — Security Evidence:** Complete

**Milestone 3 — DevSecOps Evidence:** Implemented; local and hosted CI verification should be treated as the final validation gate.

**Milestone 4 — Portfolio Audit / Release:** Pending final repository audit and CI verification.

---

## License

This project is provided for portfolio and demonstration purposes.
