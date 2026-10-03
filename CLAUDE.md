# Pipeline Compliance Hub

The source of truth for scope, architecture and the rule catalog is `docs/PLAN.md`. Read it before working.

## Working rules
- Execute milestones in order (M0 → M8). After each milestone: `ruff check . && pytest`, then commit (conventional commit message) and `git push origin main`.
- There are no live credentials. Every collector must be developed and tested against fixtures (respx). Demo mode must exercise the real collectors → normalizers → rules path.
- Report-only: never add code that writes to Azure DevOps, GitHub, SonarQube, Aikido or ServiceNow.
- Never persist secret values. Redact raw caches.
- Rules are deterministic Python. Each rule needs ≥1 PASS and ≥1 FAIL test.
- Keep `capabilities.yaml`, the deprecated-task list and the GHA mapping as data files, not code.
- If an external API detail is uncertain (especially Aikido), isolate it behind one function and leave a `# VERIFY:` comment.
