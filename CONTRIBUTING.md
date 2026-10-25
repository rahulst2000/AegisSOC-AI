# Contributing to AegisSOC AI

We welcome contributions to AegisSOC AI. Because AegisSOC AI is a mission-critical cybersecurity platform, all code changes must strictly adhere to our architectural and security standards.

## Core Rules

1. **Never weaken security controls**: Never bypass RBAC, tenant isolation, or human-in-the-loop gates.
2. **AI remains non-authoritative**: Do not write code that allows an LLM or autonomous agent to execute real security actions without human authorization.
3. **No secrets in repository**: Never commit API keys, private keys, passwords, or production connection strings.
4. **Mandatory testing**:
   - Every bug fix requires a regression test.
   - Every new feature requires unit, integration, and tenant-isolation tests.
   - Full test suite (`pytest` and `vitest`) must pass before submitting a pull request.
5. **Conventional Commits**: Format commit messages according to the Conventional Commits specification:
   - `feat(...)`: New capability or enhancement
   - `fix(...)`: Bug fix or security patch
   - `test(...)`: Unit, integration, or adversary test addition
   - `docs(...)`: Documentation and architectural notes
   - `refactor(...)`: Code cleanup without behavior change

## Local Development & Testing Workflow

### Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements-dev.txt

# Run linting and static analysis
ruff check app tests
bandit -r app -ll
pip-audit -r requirements.txt

# Run test suite
pytest -v
```

### Frontend
```bash
cd frontend
npm install
npm test
npm run build
```

### Smoke Test
```bash
python scripts/production_smoke_test.py
```
