# FAQ

## Which programming language should be used?
Any. The main requirement is that the service runs in Docker and responds via the API as described in `../openapi.yml`.

## Why does `POST /transactions` return 201 even when DECLINED?
Because the transaction is created and stored as a resource. `DECLINED` is a business result of anti-fraud and is reflected in `status/isFraud`, not in the HTTP code.

## What does “reproducibility” mean in the context of this assignment?
If the rules are the same, the request is the same, and the database has not changed - the response should be the same.
The automated testing compares responses “by meaning” and typically only ignores `id` and time fields.

## Is a refreshToken needed?
No. A single JWT token is sufficient for this assignment.

## How to distinguish between “field must not be null” and “field = null” in PUT?
- Key missing in JSON: this is a validation error → `422`.
- Key present with value `null`: this is an explicit command to “clear the field” (only allowed for nullable fields).

## Can a user’s email be changed?
No. Email cannot be changed. If a client still sends `email` in `PUT /users/*`, the service must ignore it.

## Can an ADMIN deactivate themselves?
Yes. ADMIN can deactivate any user, including themselves (`DELETE /users/{id}` sets `isActive=false`).
After deactivation, this user will not be able to log in (login will return `423`).

## How is `userId` interpreted in transactions for USER?
For the USER role, the actual `userId` is always taken from the JWT (`sub`). The `userId` field in the request body is ignored (even if provided).

## Should the service check all rules, or can it stop at the first match?
All active rules must be checked. You can’t stop at the first match because `ruleResults` is stored in the database and must be complete.

## What if a rule cannot be evaluated (unsupported tier/too complex/evaluation error)?
The service must not crash because of one rule. Such a rule is considered `matched=false`, processing continues, and `ruleResults[].description` must be filled.

## Can libraries be used for DSL parsing?
Yes. Any libraries can be used. The key is to follow the behavior described in `./dsl.md` and `../openapi.yml`.

## Does creating a rule return 422 due to “invalid DSL”?
No. `POST /fraud-rules` and `PUT /fraud-rules/{id}` save `dslExpression` as a string. To validate the expression, use `POST /fraud-rules/validate`.

## Can the assignment be submitted without a DSL parser?
Yes. At the first stage, “support tier 0” is allowed: `/fraud-rules/validate` returns `DSL_UNSUPPORTED_TIER`, and when applying rules, all rules are considered `matched=false`. This allows scoring the first points on API/DB/reproducibility, and the support tiers can be added later.

## What to do if the DSL expression is incorrect?
Validate the expression via `POST /fraud-rules/validate`.
When creating/updating a rule, the service is not required to parse the DSL and should not return `422` “for DSL”.

## Is the `ruleResults[].description` field necessary?
Yes, it’s required and must not be empty. This requirement is described in `../openapi.yml` (and is checked by automatic testing).

## Are the `position` and `near` parameters in DSL errors required?
They are necessary only for the `DSL_PARSE_ERROR` error. For other DSL errors, these fields may be absent or `null`.

## What if there are no active anti-fraud rules?
The transaction must be approved: `status=APPROVED`, `isFraud=false`.
`ruleResults` will be an empty array in this case.

## Can a transaction be created for a deactivated user?
No. `403 Forbidden` will be returned.

## What if the transaction timestamp is in the distant past?
That’s normal. The only restriction is on the far future: `timestamp` must not be greater than `now + 5 minutes` (otherwise `422`).

## What if an empty `items` array is sent in the batch request?
It will return `422`: the array must contain between 1 and 500 elements.

## What if a rule validates `user.age` and the user’s age is not specified?
Such a comparison should return `false`, meaning the rule won’t run. This rule is described in `./dsl.md`.

## How are rules sorted when `priority` is the same?
By `priority` in ascending order, and if the same, by `id` in ascending order.

## Why is a period of up to a year allowed for timeseries with `groupBy=week`?
This is an exception to the general 90-day limit: when grouped by weeks, there are fewer data points, so a period of up to 1 year is allowed.

## Is the `uniqueMerchants` field in rule statistics necessary?
No. This is an optional field: it may not be present in the response.

## What if the client sent extra fields in JSON?
Refer to the fields from `../openapi.yml`. Extra fields must be ignored and shouldn’t “crash” the request (unless they break your validation).

## Which fields in the User object may be absent?
Optional profile fields can be `null`: `age`, `region`, `gender`, `maritalStatus`.
Mandatory fields in the response - see `../openapi.yml` (the User schema).

## Which fields in the Transaction object may be absent?
Optional fields may be absent or empty: `merchantId`, `merchantCategoryCode`, `ipAddress`, `deviceId`, `channel`, `location`, `metadata`.
Mandatory fields in the response - see `../openapi.yml` (the Transaction schema).
