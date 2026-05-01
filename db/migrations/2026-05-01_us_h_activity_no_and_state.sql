-- US-H migration: add activity_no and enforce per-course uniqueness.
-- Safe for existing data:
-- 1) add nullable column
-- 2) backfill deterministic values per course
-- 3) enforce NOT NULL and unique index

ALTER TABLE activities
    ADD COLUMN IF NOT EXISTS activity_no INTEGER;

WITH numbered AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY course_id
            ORDER BY created_at, id
        ) AS generated_no
    FROM activities
    WHERE activity_no IS NULL
)
UPDATE activities a
SET activity_no = n.generated_no
FROM numbered n
WHERE a.id = n.id;

ALTER TABLE activities
    ALTER COLUMN activity_no SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_activities_course_no
    ON activities (course_id, activity_no);
