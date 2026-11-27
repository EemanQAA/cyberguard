# Hygiene score (dashboard)

Owner: Erum. Jira: SCRUM-29. Code: `Application/Features/Dashboard/DashboardService.cs`,
endpoint `GET /api/v1/dashboard`.

The score is calculated on demand from data already stored. There is no score table.

## Three components

| Component | Weight | Value (0 to 100) |
|---|---|---|
| Password habits | 40% | average of the user's last 10 password checks: Strong = 100, Fair = 60, Weak = 20 |
| Link safety | 30% | average of `100 - riskScore` over the last 10 URL scans |
| Data leaks | 30% | `100 - 25 x openHighAlerts - 10 x openMediumAlerts`, never below 0 |

"Open" means the alert status is not Reviewed.

If the user has no password checks, or no URL scans, that component is skipped and the
remaining weights are rescaled so they add up to 100% again. The data-leaks component is
**always** counted, because with zero alerts it is a valid 100.

```text
score = sum(componentValue x weight) / sum(weights used)
```

## Labels

| Score | Label |
|---|---|
| 80 or more | Excellent |
| 60 to below 80 | Good |
| 40 to below 60 | Fair |
| below 40 | At risk |

The code also has a "No score yet" label for a missing score, but it cannot happen today
because the data-leaks component is always present.

## Worked examples (check these with a calculator)

**1. Brand new user.** No checks, no scans, no alerts. Only data leaks counts:
100 x 0.30 / 0.30 = **100, Excellent**.

**2. Healthy user with one open High alert.**
- Passwords: all Strong, average 100, so 100 x 0.40 = 40
- Links: average risk 20, so (100 - 20) = 80, 80 x 0.30 = 24
- Leaks: 100 - 25 = 75, 75 x 0.30 = 22.5
- Total 86.5 over weight 1.0 = **86.5, Excellent**

**3. Weak user, no URL scans.**
- Passwords: 5 Weak and 5 Fair, average (5x20 + 5x60) / 10 = 40, so 40 x 0.40 = 16
- Links: skipped
- Leaks: 2 High and 1 Medium open, 100 - 50 - 10 = 40, so 40 x 0.30 = 12
- Total 28 over weight 0.70 = **40, Fair**

## Response fields

`score`, `label`, `passwordsChecked`, `urlsScanned`, `openAlerts`, `itemsToFix`.
Today `itemsToFix` has the same value as `openAlerts`.

## Test ideas (SCRUM-32, SCRUM-33)

The formula is inside a service that needs a database, so test it in the integration
tests, or move the arithmetic into a small static class (a good refactor) and unit test
the three examples above plus the edge cases: 0 alerts, 5 or more High alerts (the leaks
value must stop at 0), and a single URL scan with risk 100.
