# Contributing to enclout

`enclout` is currently a private repository without enforced branch protection.
Until branch protection is enabled, follow this workflow for every change.

## Required Workflow

1. Create a branch from `main`.
2. Make your changes on that branch.
3. Run local verification:
   - `./scripts/verify-m1.sh`
4. Push the branch and open a Pull Request.
5. Wait for GitHub Actions `CI` to pass.
6. Get at least one human review approval.
7. Merge only after steps 3-6 are complete.

## Do Not

- Do not push feature work directly to `main`.
- Do not merge PRs with failing `CI`.
- Do not merge without at least one approval.

## Branch and Commit Guidance

- Branch names:
  - `feat/<short-topic>`
  - `fix/<short-topic>`
  - `chore/<short-topic>`
- Commit messages:
  - `feat(scope): description`
  - `fix(scope): description`
  - `chore(scope): description`

## Security Notes

- Never commit secrets, tokens, or private keys.
- Keep `API_AUTH_TOKEN` and signing keys in environment variables or a secret manager.
