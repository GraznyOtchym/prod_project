# Glossary

Brief definitions for students. You don’t need to know everything upfront - come back here while you work.

## API / REST
A way for programs to interact over a network. In our assignment - HTTP requests and JSON responses.

## Endpoint
A specific URL + method (for example, `GET /api/v1/ping`).

## HTTP method (GET/POST/PUT/DELETE)
- `GET` - retrieve data
- `POST` - create a resource or perform an action
- `PUT` - completely replace a resource
- `DELETE` - remove (often “soft-delete” in the assignment: marking rather than physical deletion)

## HTTP status code
A number in the server response (for example, `200`, `201`, `422`). It indicates “how the request was processed,” not always “how the business logic ran.”

## JSON
A data format (objects/arrays) transmitted in requests and responses.

## OpenAPI
An API specification file: which endpoints exist, what fields are in requests/responses, what error codes.
In the assignment: `../openapi.yml`.

## JWT (JSON Web Token)
An authorisation token. The client receives it during login/registration and sends it in the header:
`Authorization: Bearer <token>`.

## HS256
A JWT signature algorithm (HMAC-SHA256). A shared secret (`RANDOM_SECRET`) is needed for verification/signing.

## Role / RBAC
The user’s role (`USER`, `ADMIN`) determines which requests are permitted.

## UUID
An identifier format (looks like `550e8400-e29b-41d4-a716-446655440000`).

## Database (PostgreSQL)
A data storage that preserves information between service restarts.

## Redis
Optional storage systems:
- Redis - typically used for caching

## Docker / docker-compose
Tools for running applications and dependencies in containers.

## Validation
Validation of input data (format, mandatory fields, value ranges). An invalid request typically returns `422`.

## Soft-delete
“Deletion” without physically removing from the database: an object is marked as inactive (`isActive=false` or `enabled=false`).

## Idempotent
A repeated request has the same effect as the first one (for example, repeatedly using `DELETE` on an already deleted resource must not break the system).

## Pagination
Splitting a list into pages: parameters `page` and `size`.

## DSL
Domain Specific Language - a “mini-language” for anti-fraud rules (for example, `amount > 10000 AND currency = ‘RUB’`).

## Tier
In the assignment, DSL can be implemented in steps: start with the simplest tier, then add capabilities.
The word `Tier` appears in documents and error codes (for example, `DSL_UNSUPPORTED_TIER`) - it’s just a name for this concept.

## Parser
Part of a program that converts a DSL string into a structure (such as a tree) for further computation.

## AST (Abstract Syntax Tree)
The “expression tree” of a DSL - the internal structure into which a program converts a rule string.
The size limit is necessary so that processing very large expressions does not slow down the testing.

## Reproducibility (determinism)
If the request is the same and the database hasn’t changed, the result should be the same (no randomness or hidden dependencies).

## Stopping at first match (short-circuit)
A situation where the program “finds a match” and stops validating the remaining rules.
This is not allowed in this assignment: results **for all** active rules must be returned.

## Side effects
Data changes “during validation”: for example, a rule suddenly modifies a user or settings.
In this assignment, rule validation must not alter data (except for saving the transaction itself and its result).
