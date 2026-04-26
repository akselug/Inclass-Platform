-- Apply this migration if your Supabase project already has the initial schema.
-- It adds the missing student roster mapping table and activity status column.

CREATE TABLE IF NOT EXISTS student_course_mapping (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (student_id, course_id)
);

ALTER TABLE activities
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'DRAFT'
    CHECK (status IN ('DRAFT', 'ACTIVE', 'ENDED'));

CREATE INDEX IF NOT EXISTS idx_mapping_student ON student_course_mapping (student_id);
CREATE INDEX IF NOT EXISTS idx_mapping_student_course ON student_course_mapping (course_id);
