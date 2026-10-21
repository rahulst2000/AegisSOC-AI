# AegisSOC AI — Developer Guide

## 1. Local Development Setup

### 1.1 Prerequisites
- Python 3.12+
- Node.js 20+ (or 22+)
- Docker & Docker Compose (optional for local non-containerized testing)

### 1.2 Setting Up the Backend
1. Create and activate a virtual environment:
   ```bash
   cd backend
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```
2. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```
3. Set up local `.env`:
   ```bash
   cp ../.env.example .env
   ```
4. Start the development server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

### 1.3 Setting Up the Frontend
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   npm install
   ```
2. Start the Vite development server:
   ```bash
   npm run dev
   ```
3. Access the SOC dashboard at `http://localhost:3000`.

---

## 2. Running Tests & Quality Checks

### 2.1 Backend Tests (Pytest)
Run the full async test suite including cross-tenant security verification:
```bash
cd backend
pytest -v --tb=short
```

### 2.2 Backend Linting & Security Analysis (Ruff)
```bash
cd backend
ruff check .
ruff format --check .
```

### 2.3 Frontend Tests (Vitest)
```bash
cd frontend
npm run test
```

### 2.4 Frontend Production Build
```bash
cd frontend
npm run build
```

---

## 3. Docker Compose Local Deployment
Start all containers (Postgres, Redis, Backend, Frontend) with health checks:
```bash
docker compose up -d --build
```
Check service logs:
```bash
docker compose logs -f backend
```
Stop containers:
```bash
docker compose down
```
