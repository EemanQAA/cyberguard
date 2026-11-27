# Definition of Done (draft)

Owner: Erum. Jira: SCRUM-34. This is a working draft. Compare it with Section 10.5 of the
System Requirements and Design Document and align the wording before submitting.

A Jira story moves to **Done** only when every box below is true.

## For every story

- [ ] The code is merged into `main` through a pull request that someone else reviewed
- [ ] `dotnet build` succeeds with no errors
- [ ] `dotnet test` passes, and the story has at least one new test where it makes sense
- [ ] No secrets in the diff (`git status` shows no `appsettings.Development.json`)
- [ ] The endpoint (if any) works in Swagger, and a screenshot is attached to the Jira card
- [ ] The Jira card is in Done with the assignee set

## For API stories

- [ ] Every endpoint under `[Authorize]` returns 401 without a token
- [ ] A user can only see and change their own data: another user's id returns 404
- [ ] Bad input returns 400, a missing item returns 404
- [ ] Nothing sensitive is logged (no passwords, no pasted text, no findings)

## For database changes

- [ ] A new EF Core migration is committed (`dotnet ef migrations add <Name>`)
- [ ] The migration was applied to Supabase and the table or column is visible

## For the scan engines (password, URL, PII)

- [ ] One unit test per rule or detector
- [ ] A documented example input with its expected result

## Per sprint

| Sprint | Done when |
|---|---|
| 1 | Skeleton builds, schema in Supabase, register/login/profile work, Docker compose runs |
| 2 | Password engine, wordlist and history work, unit tests for the engines exist |
| 3 | URL rules and geolocation work, ML model trained and exported, alerts auto-created |
| 4 | PII scanner, saved reports and alerts CRUD work, ONNX model is used by the URL scan |
| 5 | Dashboard score, CI pipeline green, integration tests pass, final documentation |
