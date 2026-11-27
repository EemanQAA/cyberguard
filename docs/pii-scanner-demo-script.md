# PII scanner: demo script

Owner: Erum. Jira: SCRUM-27. Results below were produced by the current `PiiDetector`.

## What it detects

| Type | Rule | How it is masked |
|---|---|---|
| Email | standard email pattern | first and last letter before the @ stay, the rest are `*` |
| Phone | Pakistani mobile: `+92` or `0`, then `3xx`, then 7 digits | only the last 2 characters visible |
| CNIC | `12345-1234567-1` | first 2 and last 2 characters visible |
| Card | 13 to 19 digits that pass the **Luhn** checksum | only the last 4 digits visible |
| AWS access key | `AKIA` followed by 16 capital letters or digits | only the last 4 characters visible |
| JWT | `eyJ...` three dot-separated parts | only the last 6 characters visible |

The Luhn check matters: a random 16-digit number is usually not a real card, so it is
ignored. That keeps false alarms down.

## Privacy rule

The text is scanned in memory and thrown away. Only the masked findings are saved. Never
log the text.

## Demo

1. Run the API, log in in Swagger, click Authorize.
2. `POST /api/v1/pii-scans` with this body:

```json
{ "text": "Name: Ali Khan\nEmail: ali.khan@example.com\nPhone: 0300-1234567\nCNIC: 35202-1234567-1\nCard: 4111 1111 1111 1111\nAWS: AKIAIOSFODNN7EXAMPLE" }
```

3. Expected findings:

| Type | Masked value |
|---|---|
| Email | `a******n@example.com` |
| Phone | `**********67` |
| CNIC | `35***********-1` |
| Card (Luhn valid) | `************1111` |
| AWS access key | `****************MPLE` |

4. Change the card to `4111 1111 1111 1112`. The Card finding disappears because the
   checksum fails.
5. Open the `PiiScans` table in Supabase. Show that the original text is not stored.
6. Run `GET /api/v1/history` to show the scan in the unified history.

## Ideas to extend (SCRUM-27)

- IBAN and passport number detectors, each with its own test.
- A severity per type (a card or AWS key is High, an email is Low) so alerts can be
  created automatically (this connects to SCRUM-16).
- Ignore well-known example values such as `AKIAIOSFODNN7EXAMPLE` in a flag, so the demo
  value is clearly marked as a sample.
