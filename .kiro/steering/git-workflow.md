---
inclusion: always
---

# Git Workflow — Apache Superset

## Pre-commit (REQUIRED Before Every Push)

CI will fail if pre-commit checks don't pass.

```bash
# Stage changes first
git add .

# Run on all files
pre-commit run --all-files

# If hooks auto-fix, stage and commit again
git add .
git commit --amend  # or new commit
```

For faster iteration on staged files only:

```bash
pre-commit run          # staged files only
pre-commit run mypy     # Python type checking
pre-commit run prettier # formatting
pre-commit run eslint   # frontend linting
```

Activate your Python virtual environment before running pre-commit:

```bash
source .venv/bin/activate  # adjust path to your venv
```

Common failures:
- Formatting — black, prettier, eslint will auto-fix
- Type errors — mypy failures need manual fixes
- Linting — ruff, pylint issues need manual fixes

## Pull Request Guidelines

1. Read `.github/PULL_REQUEST_TEMPLATE.md` for the current format before opening a PR
2. Include all template sections: SUMMARY, BEFORE/AFTER, TESTING INSTRUCTIONS, ADDITIONAL INFORMATION
3. Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for PR titles

```
type(scope): description

# Examples
fix(dashboard): load charts correctly
feat(sqllab): add query history export
refactor(explore): migrate to TypeScript
```

Valid types: `fix`, `feat`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`
