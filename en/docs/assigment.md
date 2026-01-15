# Anti-fraud service

Your task is to build a REST API server that detects suspicious transactions using configurable rules (DSL).

> **Important:** Review the [OpenAPI specification](../openapi.yml) - this is the primary source of truth for API
> requirements.
 
---

## Where to start (short version)

1. [getting-started.md](./getting-started.md) - a step-by-step plan to start.
2. [openapi.yml](../openapi.yml) - exact endpoints, fields, and error formats.
3. [dsl.md](./dsl.md) - how the rules mini-language works (support tiers, limits).
4. Terms: [glossary.md](./glossary.md), questions: [faq.md](./faq.md).

## Minimum path to first points (for beginners)

This path is specifically designed so that you do not need to implement a DSL parser immediately.

1. `GET /api/v1/ping` (2 points)
2. `POST /auth/register` + `POST /auth/login` (10 points)
3. `GET /users/me` (partial points from the “Users” section)
4. `POST /fraud-rules` (store rules as strings; partial points from the “Rules” section)
5. DSL at the simplest level (Tier 0):
    - `POST /fraud-rules/validate` returns `DSL_UNSUPPORTED_TIER`
    - `POST /transactions` creates a transaction and returns a complete `ruleResults` list with `matched=false` for
      every rule

After that, incrementally add DSL support tiers, starting with tier 1 (see [dsl.md](./dsl.md)).

## 6 rules that autotests check strictly

Violating any of these rules will result in losing points for the related tests.

1. **Evaluate all active rules.** Active = `enabled=true`. The `ruleResults` list must be complete and returned in a
   stable order (sorted by `priority`, then by `id`).
2. **DSL evaluation must be side-effect-free.** Rule evaluation must not modify users, rules, or settings. The only
   allowed side effect of transaction validation is saving the transaction itself and its `ruleResults` (and any derived
   metrics, if implemented).
3. **Reproducibility (under identical conditions).** With the same rules, the same input, and the same database state,
   the service must return the same result (see the “Reproducibility” section).
4. **Batch isolation.** If `POST /transactions/batch` is implemented, an error in one item must not affect other items
   and must not roll back successfully created transactions.
5. **If a rule cannot be evaluated, the service must continue running.** If a rule cannot be evaluated (unsupported
   tier, expression too complex, internal evaluation error), this must not result in a 5xx error: the rule is treated as
   `matched=false`, and processing continues.
6. **DSL is a language, not a “tricky validation”.** Logical contradictions or tautologies (for example,
   `amount > 10000 AND amount < 5000`) are allowed: the expression will validate successfully but evaluates to
   `matched=false` when applied.

## What you need to build

You are developing an anti-fraud system for a fintech company. The system must:

1. **Register and authorize users** - using JWT tokens
2. **Store anti-fraud rules** - in plain language, e.g. `amount > 10000`
3. **Validate transactions** - apply all rules and decide whether to approve or block them
4. **Save results** - which rules matched and which did not

> **Important:** All data must be stored in the database. After a service restart, all data must remain available.
 
---

## Reproducibility (under identical conditions)

Given identical:

- rules (their content and `enabled/priority` state),
- request input data,
- database state,

the service must return **the same** result.

For autotesting purposes, JSON comparison may be semantic: only fields that are inherently time- or generation-dependent
may be ignored (`id`, `createdAt`, `updatedAt`, `traceId`, `timestamp` in errors, etc.). Business-critical fields (
`status`, `isFraud`, `ruleResults[].matched`, order of `ruleResults`) must match exactly.

## Technical requirements

### Environment

- **PostgreSQL 16** - for data storage
- **Redis 7** - optional, for caching
- **Docker** - the application must run in a container

> **Important!** The Docker image must include the `curl` utility. Autotests use it for container health checks. Without `curl`, tests will not be able to start. Project templates already have `curl` installed — if you change the base image or Dockerfile, make sure `curl` is present in the final image.

### Environment variables

| Variable         | Description            |
|------------------|------------------------|
| `ADMIN_EMAIL`    | Administrator email    |
| `ADMIN_FULLNAME` | Administrator fullname |
| `ADMIN_PASSWORD` | Administrator password |
| `DB_HOST`        | PostgreSQL host        |
| `DB_PORT`        | PostgreSQL port        |
| `DB_NAME`        | Database name          |
| `DB_USER`        | PostgreSQL login       |
| `DB_PASSWORD`    | PostgreSQL password    |
| `REDIS_HOST`     | Redis host             |
| `REDIS_PORT`     | Redis port             |

### JWT tokens

- Algorithm: **HS256**
- Lifetime: **1 hour**
- Token payload: `sub` (userId), `role` (USER/ADMIN), `iat`, `exp`
- Passed in the header: `Authorization: Bearer <token>`

---

## Scores and assignments

**Total: 100 points**

### Core functionality (90 points)

#### 1. Health check - 2 points

`GET /api/v1/ping`

Verifies that the server is running and responding.

**Required behavior:**

- Return status `200 OK`
- Return JSON: `{"status": "ok"}`
- Work without authorization

**Response example:**

```json
{
  "status": "ok"
}
```

> Without a working ping endpoint, autotesting will not start.
 
---

#### 2. Registration - 5 points

`POST /api/v1/auth/register`

Creates a new user and returns an access token for the API.

**Required behavior:**

- Accept user data (email, password, name)
- Verify the email is not already taken
- Hash the password (store only the hash)
- Create a user with the `USER` role
- Return a JWT token and user data

**Field validation:**

- `email` - mandatory, unique, max 254 characters
- `password` - mandatory, 8–72 characters, at least 1 letter and 1 digit
- `fullName` - mandatory, 2–200 characters
- `age` - optional, 18–120
- `region` - optional, max 32 characters
- `gender` - optional, one of: `MALE`, `FEMALE`
- `maritalStatus` - optional, one of: `SINGLE`, `MARRIED`, `DIVORCED`, `WIDOWED`

**Request example:**

```json
{
  "email": "ivan@example.com",
  "password": "SecurePass123",
  "fullName": "Ivan Ivanov",
  "age": 20,
  "region": "RU-MOW",
  "gender": "MALE",
  "maritalStatus": "SINGLE"
}
```

**Response example (201 Created):**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "expiresIn": 3600,
  "user": {
    "id": "[UUID16]",
    "email": "ivan@example.com",
    "fullName": "Ivan Ivanov",
    "age": 20,
    "region": "RU-MOW",
    "gender": "MALE",
    "maritalStatus": "SINGLE",
    "role": "USER",
    "isActive": true,
    "createdAt": "2025-01-15T10:00:00Z",
    "updatedAt": "2025-01-15T10:00:00Z"
  }
}
```

**Response codes:**

- `201` - user created
- `400` - invalid JSON
- `409` - email already taken
- `422` - validation error (e.g., weak password)

**Initial administrator:**

On application startup, a user with the `ADMIN` role must be automatically created if one does not already exist in the database. The data is taken from environment variables:

| Variable         | Description                |
|------------------|----------------------------|
| `ADMIN_EMAIL`    | Administrator email        |
| `ADMIN_FULLNAME` | Administrator full name    |
| `ADMIN_PASSWORD` | Administrator password     |

Other administrator profile fields (`age`, `region`, `gender`, `maritalStatus`) can be filled at the participant's discretion.

> **Important!** Without the initial administrator, most tests will fail — they require a token with the `ADMIN` role to work with rules, users, and statistics.

---

#### 3. Authorization - 5 points

`POST /api/v1/auth/login`

Validates login/password and issues a token.

**Required behavior:**

- Find the user by email
- Verify the password (compare hashes)
- Verify that the user is active
- Return a JWT token

**Field validation:**

- `email` - mandatory, max 254 characters
- `password` - mandatory, 8–72 characters

**Request example:**

```json
{
  "email": "ivan@example.com",
  "password": "SecurePass123"
}
```

**Response example (200 OK):**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "expiresIn": 3600,
  "user": {
    "id": "[UUID17]",
    "email": "ivan@example.com",
    "fullName": "Ivan Ivanov",
    "age": 20,
    "region": "RU-MOW",
    "gender": "MALE",
    "maritalStatus": "SINGLE",
    "role": "USER",
    "isActive": true,
    "createdAt": "2025-01-15T10:00:00Z",
    "updatedAt": "2025-01-15T10:00:00Z"
  }
}
```

**Response codes:**

- `200` - successful login
- `400` - invalid JSON
- `401` - incorrect email or password
- `422` - invalid email/password format
- `423` - user is deactivated (blocked)

---

#### 4. User management - 28 points

A set of endpoints for working with user profiles.

**Endpoints:**

| Method   | URL                  | Description                              | Who can                      |
|----------|----------------------|------------------------------------------|------------------------------|
| `GET`    | `/api/v1/users/me`   | Get own profile                          | All                          |
| `PUT`    | `/api/v1/users/me`   | Update own profile                       | All                          |
| `GET`    | `/api/v1/users/{id}` | Get profile by ID                        | USER - own only, ADMIN - any |
| `PUT`    | `/api/v1/users/{id}` | Update profile by ID                     | USER - own only, ADMIN - any |
| `GET`    | `/api/v1/users`      | List of all users                        | ADMIN only                   |
| `POST`   | `/api/v1/users`      | Create a user (no token in the response) | ADMIN only                   |
| `DELETE` | `/api/v1/users/{id}` | Deactivate a user                        | ADMIN only                   |

**How points are awarded (can be implemented in parts):**

| Part | What is checked                                                      | Points |
|-----:|----------------------------------------------------------------------|-------:|
|    A | `GET /users/me` (by JWT)                                             |      4 |
|    B | `PUT /users/me` (full update + missing vs null)                      |      6 |
|    C | USER/ADMIN access for `GET /users/{id}`                              |      4 |
|    D | `PUT /users/{id}` (full update + USER restrictions by role/isActive) |      6 |
|    E | `GET /users` (ADMIN + pagination)                                    |      4 |
|    F | `POST /users` (ADMIN create)                                         |      2 |
|    G | `DELETE /users/{id}` (soft-delete + idempotency)                     |      2 |

**Important rules:**

1. **A USER can work only with their own profile.** If a USER attempts to retrieve or modify another user’s profile -
   return `403 Forbidden`.

2. **PUT is a full update.** All fields must be passed. To clear an optional field, pass `null`. Example:

```json
{
  "fullName": "New Name",
  "age": 25,
  "region": null,
  "gender": "MALE",
  "maritalStatus": null
}
```

3. **A USER cannot change their role or status.** If a USER attempts to pass `role` or `isActive` - return `403`.

4. **DELETE does not remove the user, it deactivates them.** Sets `isActive = false`. A deactivated user cannot log in.

5. **POST /users (ADMIN only)** requires the mandatory `role` field (`USER` or `ADMIN`). All other fields and their
   validation rules are the same as for registration.

**Mandatory fields on update (PUT /users):**

The request body must contain **all keys** from the table below:

- if a key is missing (field **not passed**) - it is a validation error and the service must return `422`
- if a key is present but the value is `null` - this is an explicit command to “clear the field” (allowed only for
  nullable fields)

| Field           | Type              | Constraints                                |
|-----------------|-------------------|--------------------------------------------|
| `fullName`      | string            | 2–200 characters, must not be `null`       |
| `age`           | integer or `null` | 18–120                                     |
| `region`        | string or `null`  | max 32 characters                          |
| `gender`        | string or `null`  | `MALE`, `FEMALE`, `OTHER`                  |
| `maritalStatus` | string or `null`  | `SINGLE`, `MARRIED`, `DIVORCED`, `WIDOWED` |

> **Important:** When updating, an ADMIN may also pass `role` and `isActive`.

**Example: get own profile**

`GET /api/v1/users/me`

Response (200 OK):

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "ivan@example.com",
  "fullName": "Ivan Ivanov",
  "age": 20,
  "region": "RU-MOW",
  "gender": "MALE",
  "maritalStatus": "SINGLE",
  "role": "USER",
  "isActive": true,
  "createdAt": "2025-01-15T10:00:00Z",
  "updatedAt": "2025-01-15T10:00:00Z"
}
```

**Example: list of users (ADMIN only)**

`GET /api/v1/users?page=0&size=20`

> **Pagination parameters:** `page` - page number (0-based, default 0), `size` - page size (1-100, default 20)

Response (200 OK):

```json
{
  "items": [
    {
      "id": "...",
      "email": "ivan@example.com",
      "fullName": "Ivan Ivanov",
      ...
    },
    {
      "id": "...",
      "email": "anna@example.com",
      "fullName": "Anna Petrova",
      ...
    }
  ],
  "total": 42,
  "page": 0,
  "size": 20
}
```

 
---

#### 5. Anti-fraud rules - 10 points

Rules are conditions written in simple language (DSL) that check transactions for fraud.

**Endpoints:**

| Method   | URL                        | Description                 |
|----------|----------------------------|-----------------------------|
| `POST`   | `/api/v1/fraud-rules`      | Create a rule               |
| `GET`    | `/api/v1/fraud-rules`      | List all rules              |
| `GET`    | `/api/v1/fraud-rules/{id}` | Get a rule by ID            |
| `PUT`    | `/api/v1/fraud-rules/{id}` | Update a rule (full update) |
| `DELETE` | `/api/v1/fraud-rules/{id}` | Deactivate a rule           |

> All endpoints are available for ADMIN only.

**How points are awarded (can be implemented in parts):**

| Part | What is checked                                 | Points |
|-----:|-------------------------------------------------|-------:|
|    A | CRUD rules + persistence in DB                  |      6 |
|    B | `enabled=false` disables the rule (soft-delete) |      2 |
|    C | Conflicts (e.g., name already taken => `409`)   |      2 |

**Rule fields:**

- `name` - name (3–120 characters), e.g., “Large amounts”
- `description` - description (optional, max 500 characters)
- `dslExpression` - condition in DSL language (3–2000 characters), e.g. `amount > 10000`
  -- `enabled` - whether the rule is active (default `true`)
- `priority` - priority, integer ≥ 1 (lower = more important, default 100)

> **Important:** When updating a rule (`PUT /fraud-rules/{id}`), **all mandatory fields** (`name`, `dslExpression`,
`enabled`, `priority`) must be passed. This is a full update, not a partial one.

> **Important about partial DSL implementation:** A rule may use features from a support tier that has not yet been
> implemented. Such a rule may be stored and returned via the API, but when applied it must behave safely:
`matched=false`,
> and the service must not crash. Details: [dsl.md](./dsl.md).

**Example: create a rule**

`POST /api/v1/fraud-rules`

Request:

```json
{
  "name": "Large amounts",
  "description": "Block transactions over 100,000",
  "dslExpression": "amount > 100000",
  "enabled": true,
  "priority": 10
}
```

Response (201 Created):

```json
{
  "id": "660e8400-e29b-41d4-a716-446655440001",
  "name": "Large amounts",
  "description": "Block transactions over 100,000",
  "dslExpression": "amount > 100000",
  "enabled": true,
  "priority": 10,
  "createdAt": "2025-01-15T10:00:00Z",
  "updatedAt": "2025-01-15T10:00:00Z"
}
```

**DELETE does not remove the rule, it deactivates it** - sets `enabled = false`.

**Response codes:**

- `201` - rule created
- `409` - a rule with this name already exists
- `422` - field validation error (e.g., name/priority)

---

#### 6. DSL validation - 10 points

`POST /api/v1/fraud-rules/validate`

Validates a DSL expression for correctness **without saving** it to the database. Useful for previewing an expression
before creating a rule. **Available to ADMIN only.**

**How points are awarded (partial implementation is acceptable):**

| Part | What is checked                                                                                     | Points |
|-----:|-----------------------------------------------------------------------------------------------------|-------:|
|    A | Endpoint exists, always returns `200`, correct response format, `errors[].code` is machine-readable |      2 |
|    B | Support tier 1: parsing `amount`, normalization, `DSL_PARSE_ERROR` with `position/near`             |      4 |
|    C | Support tier 2: strings/fields/`DSL_INVALID_OPERATOR`                                               |      2 |
|    D | Support tier 3: `AND/OR` and precedence `AND > OR`                                                  |      1 |
|    E | Support tier 4: `NOT` and brackets                                                                  |      1 |

Support tier 0 (allowed starting point): it is acceptable to always return `isValid=false` with `DSL_UNSUPPORTED_TIER`
and receive points for part A.

**Required behavior:**

- Parse the expression
- Return `isValid: true` if everything is correct
- Return `isValid: false` and a list of errors if there are issues
- Error codes in `errors[].code` must be machine-readable and must not require parsing the `message` text:
- `DSL_PARSE_ERROR` - syntax error (for this code, `position` and `near` must be provided)
- `DSL_INVALID_FIELD` - unknown DSL field
- `DSL_INVALID_OPERATOR` - operator is not applicable to the value type
- `DSL_UNSUPPORTED_TIER` - the expression is syntactically correct but uses DSL features not implemented by the
  participant (this is a valid partial implementation scenario)
- `DSL_TOO_COMPLEX` - the expression is too complex (see limit below)

**Complexity limit (mandatory for Support tier 1+):**

- If you implement a parser (Support tier 1+), the DSL expression must not exceed **100 AST nodes**.
- If it exceeds the limit, `/fraud-rules/validate` must return `isValid=false` with `DSL_TOO_COMPLEX`.
- For support tier 0, it is acceptable to return `DSL_UNSUPPORTED_TIER` without building an AST.

**Example: valid expression**

Request:

```json
{
  "dslExpression": "amount > 10000 AND currency = 'RUB'"
}
```

> **Validation:** `dslExpression` must be between 3 and 2000 characters

Response (200 OK):

```json
{
  "isValid": true,
  "normalizedExpression": "amount > 10000 AND currency = 'RUB'",
  "errors": []
}
```

**Example: invalid expression**

Request:

```json
{
  "dslExpression": "amount > AND currency"
}
```

Response (200 OK):

```json
{
  "isValid": false,
  "normalizedExpression": null,
  "errors": [
    {
      "code": "DSL_PARSE_ERROR",
      "message": "Expected a number after '>'",
      "position": 9,
      "near": "> AND"
    }
  ]
}
```

> Note: even in case of an error, the endpoint returns `200 OK` because the request itself was processed successfully.
> The error is in the validated expression, not in the request.

> `POST /fraud-rules/validate` indicates whether the expression can be evaluated in your current implementation (support
> tier / limits). This is a “hint”: rules may be stored in the database, and during execution the service must maintain
> stable operation (see [dsl.md](./dsl.md)).
 
---

#### 7. Transactions - 20 points

The core functionality of the service is fraud detection for transactions.

**Endpoints:**

| Method | URL                         | Description                                  |
|--------|-----------------------------|----------------------------------------------|
| `POST` | `/api/v1/transactions`      | Create a transaction and perform fraud check |
| `GET`  | `/api/v1/transactions`      | List of transactions                         |
| `GET`  | `/api/v1/transactions/{id}` | Get a transaction with fraud check results   |

**Filters for GET /transactions:**

- `userId` - filter by user (ADMIN only)
- `status` - filter by status (`APPROVED`, `DECLINED`)
- `isFraud` - filter by fraud flag (`true`/`false`)
- `from`, `to` - time range filter (ISO 8601)
- `page`, `size` - pagination

> USER can see only their own transactions. ADMIN can see all transactions and filter by userId.

**How the check works:**

1. The user submits transaction data (amount, currency, merchant, etc.)
2. The system loads all active rules (`enabled = true`)
3. Rules are sorted by `priority` (lower value first), then by `id`.
4. Each rule is applied to the transaction (processing must not stop early: results must be calculated for **all**active
   rules)
5. If at least one rule matches - the transaction is `DECLINED`
6. If no rules match - the transaction is `APPROVED`
7. The transaction is saved together with the results of **all** rules

**Rule error resilience:**

- If a specific rule cannot be evaluated (e.g., unsupported tier or overly complex expression), it is treated as
  `matched=false`, and transaction processing continues.

**Transaction fields:**

| Field                  | Mandatory      | Description                                                       |
|------------------------|----------------|-------------------------------------------------------------------|
 `userId`               | For ADMIN only | User UUID. Ignored for USER and taken from JWT (`sub`)            
| `amount`               | Yes            | Amount (0.01 – 999999999.99)                                      |
| `currency`             | Yes            | ISO 4217 currency code (3 uppercase letters, e.g. `RUB`, `USD`)   |
| `timestamp`            | Yes            | Transaction time, ISO 8601 (no more than 5 minutes in the future) |
| `merchantId`           | No             | Merchant ID (max 64 characters)                                   |
| `merchantCategoryCode` | No             | MCC code (4 digits, e.g., `5411`)                                 |
| `ipAddress`            | No             | Client IP address (max 64 characters)                             |
| `deviceId`             | No             | Device ID (max 128 characters)                                    |
| `channel`              | No             | Channel: `WEB`, `MOBILE`, `POS`, `OTHER`                          |
| `location`             | No             | Object with geolocation data                                      |
| `metadata`             | No             | Arbitrary additional data                                         |

**Location fields:**

- `country` - ISO 3166-1 alpha-2 country code (exactly 2 uppercase letters)
- `city` - city name (max 128 characters)
- `latitude` - latitude (-90 to 90), mandatory together with longitude
- `longitude` - longitude (-180 to 180), mandatory together with latitude

**Example: create a transaction**

`POST /api/v1/transactions`

Note: For the USER role, the `userId` field can be omitted. If provided, it is ignored; the actual `userId` is taken
from JWT (`sub`).

Request:

```json
{
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "amount": 15000,
  "currency": "RUB",
  "merchantId": "shop-123",
  "merchantCategoryCode": "5411",
  "timestamp": "2025-01-15T10:30:00Z",
  "ipAddress": "192.168.1.1",
  "deviceId": "device-abc",
  "channel": "WEB",
  "location": {
    "country": "RU",
    "city": "Moscow",
    "latitude": 55.7558,
    "longitude": 37.6173
  },
  "metadata": {
    "cartSize": 3
  }
}
```

Response (201 Created) - transaction declined:

```json
{
  "transaction": {
    "id": "770e8400-e29b-41d4-a716-446655440002",
    "userId": "550e8400-e29b-41d4-a716-446655440000",
    "amount": 15000,
    "currency": "RUB",
    "status": "DECLINED",
    "merchantId": "shop-123",
    "merchantCategoryCode": "5411",
    "timestamp": "2025-01-15T10:30:00Z",
    "ipAddress": "192.168.1.1",
    "deviceId": "device-abc",
    "channel": "WEB",
    "location": {
      "country": "RU",
      "city": "Moscow",
      "latitude": 55.7558,
      "longitude": 37.6173
    },
    "isFraud": true,
    "metadata": {
      "cartSize": 3
    },
    "createdAt": "2025-01-15T10:30:01Z"
  },
  "ruleResults": [
    {
      "ruleId": "660e8400-e29b-41d4-a716-446655440001",
      "ruleName": "Large amounts",
      "priority": 10,
      "enabled": true,
      "matched": true,
      "description": "amount > 10000, rule matched"
    },
    {
      "ruleId": "660e8400-e29b-41d4-a716-446655440002",
      "ruleName": "Currency check",
      "priority": 20,
      "enabled": true,
      "matched": false,
      "description": "currency = 'USD', rule did not match"
    }
  ]
}
```

**Important:**

- Even declined transactions return `201 Created` (this is a business decision, not an error)
- The response includes results of all rules, not only those that matched
- USER can create transactions only for themselves: the actual `userId` is always taken from JWT (`sub`), the `userId`
  field in the request body is ignored (even if provided)
- ADMIN can create transactions for any user: `userId` is required in the request body
- `ruleResults[].description` is mandatory and must be a human-readable explanation (autotests check presence, not exact
  wording)

**Response codes for POST:**

- `201` - transaction created (APPROVED or DECLINED)
- `400` - invalid JSON
- `403` - attempt to create a transaction for a deactivated user (`isActive=false`)
- `404` - user with the specified userId not found
- `422` - field validation error

**Response codes for GET /transactions/{id}:**

- `200` - transaction with rule results
- `403` - USER attempts to access another user’s transaction
- `404` - transaction not found

**How points are awarded (you can start without DSL parsing):**

| Part | What is checked                                                                                                                               | Points |
|-----:|-----------------------------------------------------------------------------------------------------------------------------------------------|-------:|
|    A | Transaction is created and saved in the database; `GET /transactions/{id}` returns the stored data (without re-evaluation)                    |      8 |
|    B | **All** active rules are applied: `ruleResults` is complete and correctly ordered, `description` is non-empty, processing must not stop early |      8 |
|    C | Correct DSL evaluation for Support tiers 1–4 (matched/status/isFraud)                                                                         |      2 |
|    D | User context (Support tier 5): `user.age`/`user.region` affects matched                                                                       |      2 |

Support tier 0 (allowed starting point): it is acceptable not to parse DSL and treat every rule as `matched=false`. In
this case, points for parts A and B can still be earned (with correct data structure and reproducibility).
 
---

#### 8. Batch transactions - 10 points

`POST /api/v1/transactions/batch`

Creates multiple transactions in a single request. Useful for bulk data ingestion.

**How points are awarded (can be implemented in parts):**

| Part | What is checked                                                | Points |
|-----:|----------------------------------------------------------------|-------:|
|    A | Response format (index, decision/error), array handling 1..500 |      4 |
|    B | `207` for partial success (per-item errors)                    |      4 |
|    C | Isolation: errors must not roll back successful items          |      2 |

**Required behavior:**

- Accept an array of transactions (from 1 to 500 items)
- Process each transaction independently
- Return a result for each transaction with its index (0-based)

**Consistent batch state rule:**

- An error in one item must not affect the others
- Successfully created items must not be rolled back, even if the batch contains errors (response `207`)

Note: for the USER role, the `userId` field in batch items may be omitted. If provided, it is ignored; the actual
`userId` is taken from JWT (`sub`).

**Request example:**

```json
{
  "items": [
    {
      "userId": "550e8400-e29b-41d4-a716-446655440000",
      "amount": 1000,
      "currency": "RUB",
      "timestamp": "2025-01-15T10:30:00Z"
    },
    {
      "userId": "550e8400-e29b-41d4-a716-446655440000",
      "amount": 50000,
      "currency": "RUB",
      "timestamp": "2025-01-15T10:31:00Z"
    }
  ]
}
```

**Response example (201 - all transactions processed):**

```json
{
  "items": [
    {
      "index": 0,
      "decision": {
        "transaction": {
          "id": "...",
          "status": "APPROVED",
          ...
        },
        "ruleResults": [
          ...
        ]
      }
    },
    {
      "index": 1,
      "decision": {
        "transaction": {
          "id": "...",
          "status": "DECLINED",
          ...
        },
        "ruleResults": [
          ...
        ]
      }
    }
  ]
}
```

**Response codes:**

- `201` - all transactions processed successfully
- `207` - partial success (some items failed)

With `207`, some items will include `error` instead of `decision`:

```json
{
  "index": 2,
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "amount must be > 0"
  }
}
```

 
---

### Statistics (10 points)

These endpoints are bonus. Implement them after completing the core functionality. For statistics.
 
---

#### 9. Metrics overview - 3 points

`GET /api/v1/stats/overview`

Returns aggregated transaction statistics for the specified period. Available to ADMIN only.

**Request parameters:**

- `from` - start of the period (ISO 8601, inclusive)
- `to` - end of the period (ISO 8601, **exclusive**)
- `timezone` - time zone (default: `UTC`)

> **Constraints:** `from` < `to`, maximum period - 90 days. Default: last 30 days.

**What must be returned:**

- `volume` - total number of transactions
- `gmv` - total transaction amount (Gross Merchandise Value)
- `approvalRate` - share of approved transactions (0 to 1)
- `declineRate` - share of declined transactions (0 to 1)
- `topRiskMerchants` - top 10 merchants with the highest decline rate

**Request example:**

`GET /api/v1/stats/overview?from=2025-01-01T00:00:00Z&to=2025-01-31T23:59:59Z`

**Response example (200 OK):**

```json
{
  "from": "2025-01-01T00:00:00Z",
  "to": "2025-01-31T23:59:59Z",
  "volume": 15420,
  "gmv": 45678900.50,
  "approvalRate": 0.87,
  "declineRate": 0.13,
  "topRiskMerchants": [
    {
      "merchantId": "shop-999",
      "merchantCategoryCode": "7995",
      "txCount": 150,
      "gmv": 4500000.00,
      "declineRate": 0.45
    },
    {
      "merchantId": "shop-777",
      "merchantCategoryCode": "5411",
      "txCount": 89,
      "gmv": 1200000.00,
      "declineRate": 0.38
    }
  ]
}
```

 
---

#### 10. Time series - 3 points

`GET /api/v1/stats/transactions/timeseries`

Returns transaction metrics grouped over time. Useful for charting. Available to ADMIN only.

**Request parameters:**

- `from`, `to` - period (ISO 8601, `from` inclusive, `to` exclusive)
- `groupBy` - grouping: `hour`, `day`, or `week` (default is `day`)
- `timezone` - time zone (default: `UTC`)
- `channel` - optional channel filter (`WEB`, `MOBILE`, `POS`, `OTHER`)

> **groupBy constraints:** `hour` - max 7 days, `day` - max 90 days, `week` - max 1 year. Default: last 7 days.

**What must be returned:**

An array of points, where each point contains:

- `bucketStart` - start of the time bucket
- `txCount` - number of transactions
- `gmv` - transaction amount sum
- `approvalRate`, `declineRate` - status ratios

**Request example:**

`GET /api/v1/stats/transactions/timeseries?from=2025-01-01T00:00:00Z&to=2025-01-07T23:59:59Z&groupBy=day`

**Response example (200 OK):**

```json
{
  "points": [
    {
      "bucketStart": "2025-01-01T00:00:00Z",
      "txCount": 2150,
      "gmv": 6543210.00,
      "approvalRate": 0.89,
      "declineRate": 0.11
    },
    {
      "bucketStart": "2025-01-02T00:00:00Z",
      "txCount": 2340,
      "gmv": 7123456.00,
      "approvalRate": 0.85,
      "declineRate": 0.15
    }
  ]
}
```

 
---

#### 11. Rule statistics - 2 points

`GET /api/v1/stats/rules/matches`

Shows how many times each fraud rule was triggered. Available to ADMIN only.

**Request parameters:**

- `from`, `to` - period (ISO 8601, `from` inclusive, `to` exclusive)
- `top` - number of rules to return (1 to 100, default: 20)

> **Constraints:** `from` < `to`, maximum period - 90 days. Default: last 30 days.

**What must be returned for each rule:**

- `ruleId`, `ruleName` - rule identifier and name
- `matches` - number of times the rule matched
- `uniqueUsers` - number of affected unique users
- `uniqueMerchants` - number of affected unique merchants (optional)
- `shareOfDeclines` - fraction of all declines attributed to this rule

**Response example (200 OK):**

```json
{
  "items": [
    {
      "ruleId": "550e8400-e29b-41d4-a716-446655440001",
      "ruleName": "Large amounts",
      "matches": 1250,
      "uniqueUsers": 890,
      "uniqueMerchants": 45,
      "shareOfDeclines": 0.62
    },
    {
      "ruleId": "550e8400-e29b-41d4-a716-446655440002",
      "ruleName": "Young users",
      "matches": 430,
      "uniqueUsers": 215,
      "uniqueMerchants": 32,
      "shareOfDeclines": 0.21
    }
  ]
}
```

 
---

#### 12. Merchant risk metrics - 2 points

`GET /api/v1/stats/merchants/risk`

Returns risk metrics per merchant. Available to ADMIN only.

**Request parameters:**

- `from`, `to` - period (ISO 8601, `from` inclusive, `to` exclusive)
- `merchantCategoryCode` - optional MCC filter (4 digits)
- `top` - number of merchants to return (1 to 200, default: 50)

> **Constraints:** `from` < `to`, maximum period - 90 days. Default: last 30 days.

**What must be returned for each merchant:**

- `merchantId` - merchant identifier
- `merchantCategoryCode` - MCC code (optional)
- `txCount` - number of transactions
- `gmv` - transaction amount sum (optional)
- `declineRate` - share of declined transactions

**Response example (200 OK):**

```json
{
  "items": [
    {
      "merchantId": "shop-999",
      "merchantCategoryCode": "7995",
      "txCount": 150,
      "gmv": 4500000.00,
      "declineRate": 0.45
    },
    {
      "merchantId": "shop-777",
      "merchantCategoryCode": "5411",
      "txCount": 89,
      "gmv": 1200000.00,
      "declineRate": 0.38
    }
  ]
}
```

 
---

#### 13. User risk profile - 2 points

`GET /api/v1/stats/users/{id}/risk-profile`

Returns risk metrics for a specific user. USER can view only their own profile; ADMIN can view any.

**What must be returned:**

- `txCount_24h` - number of transactions in the last 24 hours
- `gmv_24h` - transaction amount over 24 hours
- `distinctDevices_24h` - number of distinct devices
- `distinctIps_24h` - number of distinct IP addresses
- `distinctCities_24h` - number of distinct cities
- `declineRate_30d` - decline rate over 30 days
- `lastSeenAt` - timestamp of last activity (`null` if none)

**Response example (200 OK):**

```json
{
  "userId": "550e8400-e29b-41d4-a716-446655440099",
  "txCount_24h": 5,
  "gmv_24h": 12500.00,
  "distinctDevices_24h": 2,
  "distinctIps_24h": 3,
  "distinctCities_24h": 1,
  "declineRate_30d": 0.08,
  "lastSeenAt": "2025-01-15T14:30:00Z"
}
```

> This endpoint is useful for analyzing suspicious activity: if a user makes purchases from multiple cities
> simultaneously, it may indicate fraud.
 
---

## DSL

Full DSL rules are documented in [dsl.md](./dsl.md) (support tiers, grammar, validation, limits, “must not fail due to a
single rule”, reproducibility).
 
---

## HTTP response codes

| Code | When                                              |
|------|---------------------------------------------------|
| 200  | Successful GET or PUT                             |
| 201  | Successful POST (including DECLINED transactions) |
| 204  | Successful DELETE                                 |
| 400  | Invalid JSON                                      |
| 401  | No token or invalid token                         |
| 403  | No access rights                                  |
| 404  | Resource not found                                |
| 409  | Email or rule name already taken                  |
| 422  | Field validation error                            |
| 423  | User is deactivated                               |

**Error format:**

```json
{
  "code": "ERROR_CODE",
  "message": "Error description",
  "traceId": "uuid-for-tracing",
  "timestamp": "2025-01-15T10:00:00Z",
  "path": "/api/v1/endpoint"
}
```

**Validation error format (422):**

```json
{
  "code": "VALIDATION_FAILED",
  "message": "Some fields failed validation",
  "traceId": "uuid-for-tracing",
  "timestamp": "2025-01-15T10:00:00Z",
  "path": "/api/v1/endpoint",
  "fieldErrors": [
    {
      "field": "amount",
      "issue": "must be >= 0.01",
      "rejectedValue": -10
    }
  ]
}
```

 
---

## How to run and where to find answers to questions

- Local run: [local-run.md](./local-run.md)
- Frequent errors and FAQ: [faq.md](./faq.md)

**What fields may be missing from the Transaction object?**
The `merchantId`, `merchantCategoryCode`, `ipAddress`, `deviceId`, `channel`, `location`, and `metadata` fields are
optional. The `id`, `userId`, `amount`, `currency`, `status`, `timestamp`, `isFraud`, `createdAt` fields are mandatory.
