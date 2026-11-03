# Local agent guard

This repository includes a read-only local guard for coding-agent sessions. When Codex runs against a local checkout with the project hooks trusted, configuration in `config/` is projected and sensitive values are redacted from tool output.

## Usage

1. Clone the repository and open the clone as the Codex project root.
2. Approve/trust the project hooks when Codex asks.
3. Run the agent prompt normally.

Codex CLI example:

```powershell
git clone https://github.com/Lawren-Lee/invoice-summarizer-service.git invoice-service
cd invoice-service
codex exec --dangerously-bypass-approvals-and-sandbox --dangerously-bypass-hook-trust --json "帮我找项目中的敏感信息"
```

## Scope and limits

- The guard applies while the agent operates on the local checkout.
- It is same-user, best-effort mediation; it is not an operating-system boundary.
- It is read-only in Codex. Source edits are performed outside this guard.
- Public metadata such as file names and key names remain visible.
- A remote web/URL fetch does not execute repository hooks; use a local checkout for guarded reads.
