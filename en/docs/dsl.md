# DSL: support tiers, execution, validation

This document describes the rules for a domain-specific language (DSL), also known as a mini-language.

## Rule evaluation context

The rule is evaluated based on input data:
- `transaction` (transaction input fields)
- `user` (user profile)
- `metadata` (arbitrary additional transaction data, if used)
- `timestamp` (operation time)

This is not a requirement for a specific class/type in the code. The point is simple: DSL evaluation must not depend on the “general application state” and must not change data in the system.

## DSL support tiers

Tier N includes everything from the lower tiers.
The word `Tier` appears in tier names and error codes, for example, `DSL_UNSUPPORTED_TIER`) - this is just a name, you don’t need to change it.

### Tier 0 - authorized start
This is the mode where you **do not yet parse** the DSL or evaluate expressions.

Tier 0 rules:
- `POST /fraud-rules/validate` returns `isValid=false` and `errors` with `code=DSL_UNSUPPORTED_TIER` for any `dslExpression`.
- When applying rules to transactions, the service does not crash, and each rule is considered `matched=false` (with non-empty `ruleResults[].description`).

Tier 0 is needed to allow starting with API/DB/transactions and reproducibility, adding the parser later.

### Tier 1 (mandatory minimum)
- Fields: `amount`
- Operators: `> >= < <= = !=`
- Literals: `number`
- Expression: one `comparison` without `AND/OR/NOT/()`

### Tier 2
- Fields: `currency`, `merchantId`, `ipAddress`, `deviceId`
- Literals: `string` in single quotes (`'RUB’`)
- Only `=` and `!=` are allowed for strings (otherwise, `DSL_INVALID_OPERATOR`)

### Tier 3
- Logic: `AND`, `OR` (case-insensitive)
- Priority: `AND` higher than `OR`

### Tier 4
- `NOT` and parentheses `(...)`
- Priority: `NOT > AND > OR`

### Tier 5
- User fields: `user.age`, `user.region`
- Null semantics: if a user field is `null` → the corresponding comparison returns `false`

## Do not “simplify” expressions

DSL validation and evaluation **must not** attempt to simplify expressions “smartly”.
Example: `amount > 10000 AND amount < 5000`:
- must be validated as a correct expression;
- when applied, must return `matched=false`;
- the service must not crash.

## Grammar (EBNF)

```
expression = term { "OR" term }
term   	= factor { "AND" factor }
factor 	= "NOT" factor | comparison | "(" expression ")"
comparison = field operator value
field  	= "amount" | "currency" | "merchantId" | "ipAddress" | "deviceId"
       	| "user.age" | "user.region"
operator   = ">" | ">=" | "<" | "<=" | "=" | "!="
value  	= number | string
string 	= "'" { character } "'"
number 	= digit { digit } [ "." digit { digit } ]
```

## How to apply rules to a transaction (runtime)

- When creating a transaction, the service must apply **all** active rules (`enabled=true`).
- Rules must be sorted in a reproducible order: `priority ASC`, then `id ASC`.
- Results must be evaluated for each rule, and `ruleResults` must contain all rules in the specified order.
- `GET /transactions/{id}` returns the stored `ruleResults` and does not reevaluate them.

### If a rule cannot be evaluated, the service continues to operate

If a rule cannot be evaluated (for example, it uses an unsupported tier, the expression is too complex, or an evaluation error occurs) the service must:
- not crash or return 5xx error because of one rule;
- consider the result of this rule as `matched=false`;
- return a `ruleResults` element for this rule;
- fill `ruleResults.description` with a human-readable explanation (content is not compared, only presence is checked).

## DSL validator

### Where validation occurs
- `POST /fraud-rules/validate` - validation without saving (always `200`, result in `isValid`).
- `POST /fraud-rules`, `PUT /fraud-rules/{id}` - create/update a rule and save `dslExpression` as a string; DSL validation is done via a separate call to `/fraud-rules/validate`.

### Error codes (machine-readable)
- `DSL_PARSE_ERROR` - syntax error (`position` and `near` are required for this code).
- `DSL_INVALID_FIELD` - unknown DSL field.
- `DSL_INVALID_OPERATOR` - operator inapplicable to the value type (for example, `currency > ‘RUB’`).
- `DSL_UNSUPPORTED_TIER` - expression is correct but uses DSL features above the implemented tier (partial implementation).
- `DSL_TOO_COMPLEX` - expression exceeds the complexity limit (see below).

### Complexity limit (autotests protection)

Validation must limit the size of the “expression tree” **if you implement parsing (Tier 1+)**.

Rule:
- if the expression exceeds **100 AST nodes**, `/fraud-rules/validate` must return `isValid=false` and `DSL_TOO_COMPLEX`;
- DSL restrictions when creating/updating a rule are applied via `/fraud-rules/validate` (the creation process itself is not required to parse the DSL).

For tier 0, it’s acceptable to always return `DSL_UNSUPPORTED_TIER` without building an AST (this is simpler and safer at the start).

### Normalization
- `AND/OR/NOT` are converted to uppercase.
- There is one space around binary operators: `amount>10` → `amount > 10`.
