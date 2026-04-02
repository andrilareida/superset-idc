---
inclusion: always
---

# Testing — Apache Superset

## Strategy (Preference Order)
1. Unit tests
2. Integration tests
3. End-to-end tests (sparingly)

## Frontend Testing
- Jest + React Testing Library for component tests
- NO Enzyme (removed)
- Use `test()` instead of `describe()` — follow [avoid nesting when testing](https://kentcdodds.com/blog/avoid-nesting-when-youre-testing)
- Playwright for E2E — Cypress is deprecated and will be removed

## Test Helpers

### TypeScript
- `superset-frontend/spec/helpers/testing-library.tsx` — custom `render()` with providers
- `createWrapper()` — Redux/Router/Theme wrapper
- `selectOption()` — Select component helper

### Python
- `SupersetTestCase` — base class in `tests/integration_tests/base_tests.py`
- `@with_config` — config mocking decorator
- `@with_feature_flags` — feature flag testing
- `login_as()`, `login_as_admin()` — authentication helpers
- `create_dashboard()`, `create_slice()` — data setup utilities

### Mock Patterns
- Use `MagicMock()` for config objects
- Avoid `AsyncMock` for synchronous code
- API tests: update expected columns when adding new model fields

## Running Tests

```bash
# Frontend
npm run test                            # all tests
npm run test -- filename.test.tsx      # single file

# E2E (Playwright)
npm run playwright:test                 # all tests
npm run playwright:ui                   # interactive UI mode
npm run playwright:headed               # see browser during tests
npx playwright test tests/auth/login.spec.ts
npm run playwright:debug tests/auth/login.spec.ts

# E2E (Cypress — DEPRECATED)
cd superset-frontend/cypress-base
npm run cypress-run-chrome
npm run cypress-debug

# Backend
pytest                                  # all tests
pytest tests/unit_tests/specific_test.py
pytest tests/unit_tests/
```

If pytest fails with database/setup issues, ask the user to run the test environment setup.
