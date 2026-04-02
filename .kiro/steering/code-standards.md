---
inclusion: always
---

# Code Standards — Apache Superset

Apache Superset is a data visualization platform with Flask/Python backend and React/TypeScript frontend.

## Ongoing Refactors (Avoid Deprecated Patterns)

### Frontend Modernization
- NO `any` types — use proper TypeScript types
- NO JavaScript files — convert to TypeScript (.ts/.tsx)
- Use `@superset-ui/core` — don't import Ant Design directly, prefer Ant Design component wrappers from `@superset-ui/core/components`
- Use antd theming tokens — prefer antd tokens over legacy theming tokens
- Avoid custom CSS and styles — follow antd best practices

### Backend Type Safety
- Add type hints — all new Python code needs proper typing
- MyPy compliance — run `pre-commit run mypy` to validate
- SQLAlchemy typing — use proper model annotations

### UUID Migration
- Prefer UUIDs over auto-incrementing IDs — new models should use UUID primary keys
- Use UUIDs in public APIs instead of internal integer IDs
- Existing models — add UUID fields alongside integer IDs for gradual migration

## TypeScript Frontend
- Avoid `any` types — use proper TypeScript, reuse existing types
- Functional components with hooks
- `@superset-ui/core` for UI components (not direct antd)
- Jest for testing (NO Enzyme)
- Redux for global state where it exists, hooks for local

## Python Backend
- Type hints required for all new code
- MyPy compliant — run `pre-commit run mypy`
- SQLAlchemy models with proper typing
- pytest for testing
- Use negation operator: `~Model.field` instead of `== False` to avoid ruff E712 errors

## Apache License Headers
- New files require ASF license headers
- LLM instruction files are excluded (in `.rat-excludes`)

## Code Comments
- Avoid time-specific language — don't use "now", "currently", "today" in comments
- Write timeless comments that remain accurate regardless of when they're read

## Documentation Requirements
- `docs/` — update for any user-facing changes
- `UPDATING.md` — add breaking changes here
- Docstrings required for new functions/classes

## Developer Portal: Storybook-to-MDX
Stories are the single source of truth for the Developer Portal.

- Fix issues in the story, not the generator
- Use `export default { title: '...' }` (inline), not `const meta = ...; export default meta;`
- Name interactive stories `Interactive${ComponentName}`
- Define `args` for default prop values
- Define `argTypes` at the story level with control types and descriptions
- Use `parameters.docs.gallery` for size×style variant grids
- Use `parameters.docs.sampleChildren` for components that need children
- Use `parameters.docs.liveExample` for custom live code blocks
- Use `parameters.docs.staticProps` for complex object props

Generator: `docs/scripts/generate-superset-components.mjs`
Wrapper: `docs/src/components/StorybookWrapper.jsx`
Output: `docs/developer_portal/components/`
