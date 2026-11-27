# Password checker: how it works

Owner: Zoya Khalid. Jira: SCRUM-18 (strength engine), SCRUM-19 (wordlist), SCRUM-20 (history).

## Privacy rule

The raw password **never reaches the server**. The strength engine runs on the client
(`CyberGuard.Shared/PasswordAnalysis/PasswordAnalyzer.cs`). Only the result is sent to
`POST /api/v1/password-checks`:

```json
{ "entropyBits": 61.4, "rating": 2, "matchedCommonOrWordlist": false }
```

Rating values: `0` Weak, `1` Fair, `2` Strong.

## Rating rules (from the code)

| Condition | Rating |
|---|---|
| In the common-password list or in the user's custom wordlist (case-insensitive) | Weak |
| Entropy below 40 bits | Weak |
| Entropy from 40 up to (not including) 60 bits | Fair |
| Entropy 60 bits or more | Strong |

Entropy = `length * log2(pool)`, where the pool is the sum of the character classes used:
lowercase 26, uppercase 26, digits 10, symbols 32.

Rule flags returned for the checklist in the UI: minimum length 12, upper and lower case,
digit, symbol, no repeated pattern (four identical characters in a row, or a substring
that repeats straight away such as `abab` or `123123`).

## Worked examples

| Password | Pool | Entropy | Rating |
|---|---|---|---|
| `abcdefgh` | 26 | 8 x 4.70 = 37.6 | Weak |
| `Abcdefgh` | 52 | 8 x 5.70 = 45.6 | Fair |
| `Tr0ub4dor&3xplosion!9Q` | 94 | 22 x 6.55 = 144.2 | Strong |
| `password` | 26 | 37.6 | Weak (common list) |

## Wordlist (SCRUM-19)

Users keep a personal list of words they must never use as passwords (pet names,
birthdays). Endpoints under `/api/v1/wordlist`: list, add, update, delete. The database
enforces one entry per `(UserId, Word)`.

## History (SCRUM-20)

`GET /api/v1/history` returns password checks, URL scans and PII scans in one list so the
user sees everything they did in one place.

## Known limits (ideas for your extension work)

- Keyboard walks such as `qwertyuiop` are not detected.
- The common-password list has 12 entries. Loading a larger list (for example the top
  10,000) would make the check much stronger.
- Entropy assumes every character is random, so `Password1!` scores higher than it
  deserves. Penalising dictionary words is a good Sprint 2 improvement.
