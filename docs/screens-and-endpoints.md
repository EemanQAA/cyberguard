# Screens and the endpoints behind them

Owner: Erum. Jira: SCRUM-34 (Figma mockups). Use this as the checklist for the mockups:
each screen needs a frame in Figma, and each frame lists the endpoint it will call.

| # | Screen | Main elements | Endpoints | Owner of the logic |
|---|---|---|---|---|
| 1 | Register / Login | email, password, error messages | `POST auth/register`, `POST auth/login` | Eeman |
| 2 | Profile | email, change email, delete account | `GET/PUT/DELETE users/me` | Eeman |
| 3 | Dashboard | hygiene score, label, counters, items to fix | `GET dashboard` | Erum |
| 4 | Password checker | password field, strength meter, rule checklist, save result | `POST password-checks` (result only) | Zoya |
| 5 | Wordlist | list, add, edit, delete words | `GET/POST/PUT/DELETE wordlist` | Zoya |
| 6 | URL scanner | URL field, score, label, reasons list, map | `POST url-scans`, `GET url-scans/{id}` | Maha |
| 7 | URL scan detail | verdict buttons (Safe / Phishing), save report | `PATCH url-scans/{id}/verdict`, `POST reports` | Maha |
| 8 | PII scanner | text box, findings with masked values | `POST pii-scans` | Erum |
| 9 | Saved reports | list, search, filter by type, edit note, delete | `GET/POST/PATCH/DELETE reports` | Erum |
| 10 | Alerts | list, filter by status, mark read, mark all, delete | `GET alerts`, `PATCH alerts/{id}/status`, `POST alerts/mark-all-read` | Eeman |
| 11 | History | one list of every check and scan, filters | `GET history` | Zoya |

(Every endpoint is under `/api/v1/`.)

## States every screen needs in the mockup

- Loading
- Empty (no data yet), with a clear next action
- Error (network or 401, which sends the user to login)
- Success

## Design rules from the project

- Never show a raw password, raw scanned text or full secret anywhere. Show masked values
  only.
- Colours for risk: Low green, Medium amber, High red, and never colour alone (add the
  word Low / Medium / High).
- The password strength meter is computed in the browser, so it updates as the user types.
