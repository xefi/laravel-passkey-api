# AGEND.md

## 1. Project Goal

The goal of this project is to build a **Laravel API-first package** that enables **Passkeys / WebAuthn authentication** on the server side.

The package must allow developers to integrate Passkeys into Laravel applications through a **secure, standards-compliant, and developer-friendly API**.

The library should provide:

* Passkey registration
* Passkey authentication
* WebAuthn challenge management
* Attestation validation
* Assertion validation
* Secure credential storage
* Easy integration with Laravel APIs

The implementation must follow the **WebAuthn standard and FIDO ecosystem recommendations**.

---

# 2. Project Vision

This package must be:

* **API-first**
* **secure by design**
* **WebAuthn compliant**
* **framework-idiomatic for Laravel**
* **extensible**
* **testable**
* **maintainable**

The package must support use cases such as:

* REST APIs
* SPA backends
* mobile backends
* microservice architectures

The package must **not depend on any specific frontend implementation**.

---

# 3. Functional Scope

The package must implement the core **WebAuthn ceremonies**.

## Registration Ceremony

Responsibilities:

* generate registration challenge
* build `PublicKeyCredentialCreationOptions`
* validate attestation response
* extract credential public key
* store credential information

## Authentication Ceremony

Responsibilities:

* generate authentication challenge
* build `PublicKeyCredentialRequestOptions`
* validate assertion response
* verify signature
* validate authenticator data
* validate signCount

## Credential Management

The package must support:

* multiple passkeys per user
* credential lifecycle
* signCount tracking
* credential lookup
* credential revocation if needed

---

# 4. Security Responsibilities

Security is the **highest priority** of the project.

The package must correctly validate:

* challenge
* RP ID
* origin
* signature
* authenticator data
* clientDataJSON
* signCount

The package must prevent:

* replay attacks
* signature bypass
* origin spoofing
* RP ID mismatch

All security-sensitive logic must strictly follow the **WebAuthn specification**.

Reference:

[https://www.w3.org/TR/webauthn-3/](https://www.w3.org/TR/webauthn-3/)

---

# 5. Package Architecture

The package must follow **Laravel package best practices**.

### Expected components

The package should expose:

* services
* contracts (interfaces)
* DTOs
* validators
* events
* configuration

Controllers must **not be enforced by the package**.

The package should remain **framework-agnostic at the HTTP layer** whenever possible.

---

# 6. Separation of Responsibilities

The architecture must clearly separate:

### WebAuthn option generation

Responsible for creating:

* `PublicKeyCredentialCreationOptions`
* `PublicKeyCredentialRequestOptions`

### WebAuthn validation

Responsible for validating:

* attestation
* assertion
* signature
* authenticator data

### Challenge management

Responsible for:

* generating secure challenges
* storing challenges
* validating challenge integrity

### Credential storage

Responsible for:

* storing credential ID
* storing public key
* storing signCount
* linking credentials to users

---

# 7. Technical Domains

The project requires strong knowledge in the following areas.

## Laravel

* Service Container
* Service Providers
* Contracts
* Events
* Configuration
* Testing
* Package development

Documentation:

[https://laravel.com/docs](https://laravel.com/docs)

---

## WebAuthn

Important concepts:

* registration ceremony
* authentication ceremony
* attestation
* assertion
* authenticator data
* clientDataJSON
* challenge
* RP ID
* origin
* signature verification
* signCount
* user verification

Reference:

[https://www.w3.org/TR/webauthn-3/](https://www.w3.org/TR/webauthn-3/)

---

## Passkeys

Important concepts:

* discoverable credentials
* multi-device credentials
* syncable authenticators
* device-bound credentials
* account recovery strategies

Reference:

[https://passkeys.dev](https://passkeys.dev)

---

## Authentication Security

Security guidelines should follow:

* NIST SP 800-63B
* OWASP authentication guidelines
* FIDO Alliance recommendations

References:

[https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B.pdf)

[https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

# 8. Company Development Rules

The following rules are **mandatory** for this project.

## English Only

All documentation, code, commit messages, and discussions must be written **in English**.

No other language is supported in the repository.

---

## No Inline Code Comments

Inline comments inside the code are **forbidden**.

All documentation must be written using **PHPDoc / DocBlocks**.

### Incorrect

```php
// Verify signature
$validator->validate($assertion);
```

### Correct

```php
/**
 * Validate the WebAuthn signature returned by the authenticator.
 */
$validator->validate($assertion);
```

---

## Code Must Be Self-Explanatory

Code should be:

* readable
* explicit
* minimal
* self-documented through naming

Method and variable names must clearly express intent.

---

## Follow Laravel Conventions

The codebase must respect:

* Laravel conventions
* PSR standards
* modern PHP practices

---

## Mandatory Testing

All features must include tests.

Tests may include:

* unit tests
* integration tests
* feature tests when appropriate

The package must be testable **independently of a Laravel application**.

---

# 9. Technical Decision Documentation

Important technical decisions must be documented using **ADR (Architecture Decision Records)**.

Each ADR must include:

* context
* problem
* possible solutions
* chosen solution
* rationale
* consequences

---

# 10. Technical Priorities

Project priorities are:

1. Security
2. WebAuthn standard compliance
3. Public API stability
4. Testability
5. Maintainability
6. Developer experience

