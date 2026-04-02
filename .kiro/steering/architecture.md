---
inclusion: always
---

# Architecture — Apache Superset

## Key Directories

```
superset/
├── superset/                    # Python backend (Flask, SQLAlchemy)
│   ├── views/api/              # REST API endpoints
│   ├── models/                 # Database models
│   └── connectors/             # Database connections
├── superset-frontend/src/       # React TypeScript frontend
│   ├── components/             # Reusable components
│   ├── explore/                # Chart builder
│   ├── dashboard/              # Dashboard interface
│   └── SqlLab/                 # SQL editor
├── superset-frontend/packages/
│   └── superset-ui-core/       # UI component library (USE THIS)
├── tests/                      # Python/integration tests
├── docs/                       # Documentation (update for user-facing changes)
└── UPDATING.md                 # Breaking changes log
```

## API Structure
- `/api.py` — REST endpoints with decorators and OpenAPI docstrings
- `/schemas.py` — Marshmallow validation schemas for OpenAPI spec
- `/commands/` — Business logic classes with `@transaction()` decorators
- `/models/` — SQLAlchemy database models
- OpenAPI docs auto-generated at `/swagger/v1` from docstrings and schemas

## Migration Files
- Location: `superset/migrations/versions/`
- Naming: `YYYY-MM-DD_HH-MM_hash_description.py`
- Use helpers from `superset.migrations.shared.utils` for database compatibility
- Import utilities instead of raw SQLAlchemy operations

## Security & Feature Patterns
- RBAC — role-based access via Flask-AppBuilder
- Feature flags — control feature rollouts
- Row-level security — SQL-based data access control

## Key Project Files
- `superset-frontend/package.json` — frontend build scripts (`npm run dev` on port 9000)
- `pyproject.toml` — Python tooling (ruff, mypy configs)
- `requirements/` — Python dependencies (base.txt, development.txt)

## Environment Validation

```bash
curl -f http://localhost:8088/health || echo "Setup required"
```

If the health check fails, refer to the [Working with LLMs](https://superset.apache.org/docs/contributing/development#working-with-llms) setup docs.
