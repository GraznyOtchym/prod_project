# Getting started (even if it’s scary)

The purpose of this file is to help you start the project and reach the first passing checks step by step.

## 0) Read these 4 things (in this order)

1. `../openapi.yml` - what endpoints and formats are expected.
2. `./assignment.md` - points and consistent state rules (what most often breaks the autotests).
3. `./dsl.md` - how the mini rule language is structured and what support tiers exist.
4. `./faq.md` - short answers to common questions (to avoid wasting time on “why is it like this”).

## 1) Minimum “skeleton” that’s already useful

Build the service so that:
- the container starts;
- `GET /api/v1/ping` returns `{"status":"ok"}`.

This alleviates the fear that “nothing works” and gives you a starting point.

## 2) Do one endpoint at a time (and test immediately)

Recommended order:
1. Registration/login (JWT).
2. User: `GET /users/me`.
3. User: `PUT /users/me` (full update + difference between “key missing” and `null`).
4. Rules: creation/update/list/deactivation (without complex logic).
5. DSL expression validation: `/fraud-rules/validate` (support tier 1).
6. Transactions: `POST /transactions` + `GET /transactions/{id}` (without rules and with rules).
7. Batch: `POST /transactions/batch` (element isolation).

At each step, it’s useful to run minimal local tests (the most basic checks; organizers publish these separately).

## 3) How to earn points honestly with partial DSL implementation

You can implement DSL “by support tiers”:
- First, make tier 1 (comparing `amount` with a number).
- Then add the next tiers only when the basic functionality is stable.

Important! If you don’t yet know how to evaluate an expression:
- the service must not crash;
- the rule must be considered `matched=false`;
- `ruleResults[].description` must be non-empty.

## 4) Recipe for struggling participants: “minimum + quality”

If time is limited, it’s better to implement less functionality but do it correctly:
- persistence to database (so everything is saved after restart);
- reproducibility of results (under the same conditions);
- rule that “all active rules provide ruleResults”;
- proper handling of errors and codes.

## 5) How to avoid failing the autotests (most common pitfalls)

- Don’t stop at the first rule match: `ruleResults` must be complete.
- Don’t introduce “randomness”: the same request with the same database must produce the same result.
- Don’t confuse HTTP code with business result: `POST /transactions` returns `201` even for `DECLINED`.
- In `PUT /users/*`, distinguish between “key missing” and `null` (see `./assignment.md`).
