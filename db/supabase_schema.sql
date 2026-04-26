-- InClass Platform core schema for Supabase (PostgreSQL)
-- Supports US-B and student auth flows used by US-C.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    school_email TEXT NOT NULL UNIQUE,
    full_name TEXT,
    role TEXT NOT NULL CHECK (role IN ('student', 'instructor', 'admin')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS courses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    course_code TEXT NOT NULL UNIQUE,
    course_name TEXT NOT NULL,
    term TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS instructor_course_mapping (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instructor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (instructor_id, course_id)
);

CREATE TABLE IF NOT EXISTS student_course_mapping (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (student_id, course_id)
);

CREATE TABLE IF NOT EXISTS activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'ACTIVE', 'ENDED')),
    starts_at TIMESTAMPTZ,
    due_at TIMESTAMPTZ,
    max_score NUMERIC(6,2) NOT NULL DEFAULT 100,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (school_email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
CREATE INDEX IF NOT EXISTS idx_mapping_instructor ON instructor_course_mapping (instructor_id);
CREATE INDEX IF NOT EXISTS idx_mapping_course ON instructor_course_mapping (course_id);
CREATE INDEX IF NOT EXISTS idx_mapping_student ON student_course_mapping (student_id);
CREATE INDEX IF NOT EXISTS idx_mapping_student_course ON student_course_mapping (course_id);
CREATE INDEX IF NOT EXISTS idx_activities_course ON activities (course_id);

-- Optional seed for quick smoke test; replace domain/email before use.
-- INSERT INTO users (school_email, full_name, role)
-- VALUES ('student1@mef.edu.tr', 'Student One', 'student')
-- ON CONFLICT (school_email) DO NOTHING;
