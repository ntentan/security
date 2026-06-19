# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-19

### Added

- **Authentication Middleware (`AuthMiddleware`)**:
  - Ensures requests are from authenticated sessions before passing down the pipeline.
  - Supports setting excluded path prefixes that bypass authentication.
  - Extensible authentication provider structure through `AuthProviderFactory` (including `HttpRequestProvider`).
  - Support for custom user models via `AuthUserModelFactory`.

- **CSRF Protection Middleware (`CsrfMiddleware`)**:
  - Protects state-changing HTTP requests (`POST`, `PUT`, `PATCH`, `DELETE`) with CSRF tokens.
  - Resolves tokens from request headers (`X-CSRF-Token`) or parsed body params (`csrf_token`).
  - Allows configuring path exceptions using prefix matching or regular expressions.
  - Optional client-side CSRF token cookie sync option (`set_cookie`).

- **Rate Limiting Middleware (`RateLimitMiddleware`)**:
  - Controls client request volumes using IP identification (`REMOTE_ADDR`).
  - Configurable max attempts limit and time window.
  - Issues `429 Too Many Requests` status responses with a `Retry-After` header.
