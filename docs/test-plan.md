# Test plan

Owner: Erum. Jira: SCRUM-32 (unit tests), SCRUM-33 (integration tests).

## Levels

| Level | Where | What it proves |
|---|---|---|
| Unit | `tests/CyberGuard.UnitTests` | the engines (`PasswordAnalyzer`, `UrlRiskEngine`, `PiiDetector`, `UrlFeatureExtractor`) give the right answers |
| Integration | to be created: `tests/CyberGuard.IntegrationTests` | endpoints, auth and database work together |
| Manual | Swagger or `docs/api-requests.http` | quick check before a demo |

Run unit tests: `dotnet test`.

## Unit test coverage today

| Engine | Test file | Owner |
|---|---|---|
| PasswordAnalyzer | `PasswordAnalyzerTests.cs`, `PasswordAnalyzerExtraTests.cs` | Zoya |
| UrlRiskEngine | `UrlRiskEngineTests.cs`, `UrlRiskEngineExtraTests.cs` | Maha |
| UrlFeatureExtractor | `UrlFeatureExtractorTests.cs` | Maha |
| PiiDetector | `PiiDetectorTests.cs` | Erum |

## Integration test cases (SCRUM-33)

Use `WebApplicationFactory<Program>` (`Program` is already public for this) with a test
database. Each case lists the expected status.

### Authentication

| # | Case | Expected |
|---|---|---|
| A1 | Register with a valid email and password | 201 |
| A2 | Register with the same email twice | 400 |
| A3 | Register with a weak password (under 8 characters) | 400 |
| A4 | Login with the right password | 200 with `accessToken` |
| A5 | Login with a wrong password | 401 |
| A6 | Any protected endpoint without a token | 401 |
| A7 | Refresh with a valid cookie | 200, new token |
| A8 | Reuse an old refresh token | 401 and the whole token family is revoked |

### Cross-user access (the most important test)

User A creates a record. User B, with their own token, tries to use it.

| # | Case | Expected |
|---|---|---|
| X1 | B reads A's URL scan by id | 404 |
| X2 | B deletes A's URL scan | 404, and A can still read it |
| X3 | B reads A's PII scan by id | 404 |
| X4 | B changes the status of A's alert | 404 |
| X5 | B edits the note of A's saved report | 404 |
| X6 | B lists scans | only B's own items, never A's |

### Per module

| Module | Cases |
|---|---|
| Password checks | create, list (paged), get, delete; missing id gives 404 |
| Wordlist | add, duplicate word (should be 409, see known issue 1), update, delete |
| URL scans | scan a valid URL gives 201 with score and reasons; invalid text gives score 100; set verdict gives 204 |
| PII scans | scan text with an email gives a masked finding; the raw text is never in the response |
| Reports | bookmark with exactly one scan id works; with none or two should give 400 (see known issue 1) |
| Alerts | list, filter by status, mark one read, mark all read, delete |
| Dashboard | new user: score 100 and label Excellent; after weak passwords the score drops |
| History | contains items of all three types, newest first |
| Health | `GET /api/v1/health` is 200 when the database is reachable |

## Known issues found while writing this plan

1. **Validation errors return 500.** `WordlistService` throws `InvalidOperationException`
   for a duplicate word, and `SavedReportService` throws it when a report does not
   reference exactly one scan. `Program.cs` has one exception handler that turns every
   exception into **500**. These cases should be **409 Conflict** (duplicate) and
   **400 Bad Request** (bad report). Suggested fix: a small custom exception type (for
   example `ValidationException`) that the handler maps to 400, plus a test for each case.
   Talk to Eeman before changing `Program.cs`.

## Privacy checks (manual, once per sprint)

1. Scan text containing a fake card number. Open the `PiiScans` table in Supabase. The raw
   text must not be there, only masked findings.
2. Check the API console log. It must not show the pasted text or any password.
