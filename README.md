# Inclass-Platform

US-B setup deliverables for Team Member 2 are implemented in this repository:

- Supabase schema SQL: `db/supabase_schema.sql`
- Student auth verification logic: `app/services.py` (`fetch_registered_student_by_email`)
- Student login endpoint: `POST /auth/google/student`
- DB connectivity check endpoint: `GET /health/db`

## 1) Create schema in Supabase

1. Open Supabase project dashboard.
2. Go to SQL Editor.
3. Paste and run the full file from `db/supabase_schema.sql`.
4. Confirm these tables exist: `users`, `courses`, `instructor_course_mapping`, `student_course_mapping`, `activities`.

If your database was already initialized before this update, also run:

- `db/migrations/2026-04-26_us_b_schema_patch.sql`

## 2) Configure environment

Copy `.env.example` into `.env` and set real values:

- `GOOGLE_CLIENT_ID`
- `SCHOOL_EMAIL_DOMAIN`
- `DATABASE_URL` (Supabase Postgres connection string)
- `JWT_SECRET`

## 3) Run service locally

Install dependencies and run:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## 4) Verify Definition of Done

### A. Database URL is working

Call:

```bash
curl http://127.0.0.1:8000/health/db
```

Expected response:

```json
{"database":"ok"}
```

### B. Student exists in users table

Insert at least one student user in Supabase SQL editor if needed:

```sql
INSERT INTO users (school_email, full_name, role)
VALUES ('student1@mef.edu.tr', 'Student One', 'student')
ON CONFLICT (school_email) DO NOTHING;
```

### C. Student can authenticate and receive JWT

Send a verified Google ID token to the student endpoint:

```bash
curl -X POST http://127.0.0.1:8000/auth/google/student \
	-H "Content-Type: application/json" \
	-d '{"id_token":"<GOOGLE_ID_TOKEN>"}'
```

Expected behavior:

- Returns `200 OK` with `access_token`, `user_id`, `role=student`, and `email`.
- Returns `404` if the email is not a registered student in `users`.