-- Seed the two default courses previously shown by the frontend mock data.
-- Safe to run more than once.

INSERT INTO courses (course_code, course_name, term)
VALUES
    ('INTRO-CS', 'Introduction to Computer Science', 'Basic concepts of programming.'),
    ('ADV-SE', 'Advanced Software Engineering', 'Design patterns and scalable architectures.')
ON CONFLICT (course_code) DO UPDATE SET
    course_name = EXCLUDED.course_name,
    term = EXCLUDED.term;

INSERT INTO instructor_course_mapping (instructor_id, course_id)
SELECT instructor.id, course.id
FROM users instructor
CROSS JOIN courses course
WHERE instructor.school_email = 'instructor@mef.edu.tr'
  AND instructor.role = 'instructor'
  AND course.course_code IN ('INTRO-CS', 'ADV-SE')
ON CONFLICT (instructor_id, course_id) DO NOTHING;
