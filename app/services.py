"""
@file services.py
@brief User and Course management services for the InClass Platform.
@details This module provides asynchronous database operations for fetching user records, 
         managing instructor courses, and updating user credentials.
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
from fastapi import HTTPException, status
from asyncpg.exceptions import UniqueViolationError
from jose import jwt
from passlib.context import CryptContext

# Global pool for the service layer
db_pool: asyncpg.Pool | None = None

JWT_SECRET: str = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

logger = logging.getLogger("inclass.auth")

_AUTO_SCORING_STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "for",
    "from", "has", "have", "how", "in", "into", "is", "it", "its", "of",
    "on", "or", "that", "the", "their", "then", "there", "these", "this",
    "to", "was", "were", "what", "when", "where", "which", "why", "will",
    "with", "your", "define", "describe", "explain", "identify",
    "understand", "use", "using",
}


class PasswordHasher:
    """
    @brief Hashes and verifies passwords using bcrypt via CryptContext.
    @details Provides class methods to generate secure password hashes and check
             plain-text inputs against stored hashes for authentication.
    """

    _context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def hash(cls, password: str) -> str:
        """
        @brief Hashes a plain-text password using bcrypt.
        @param password The plain-text password to hash.
        @return The hashed password string.
        """
        return cls._context.hash(password)

    @classmethod
    def verify(cls, plain_password: str, hashed_password: str) -> bool:
        """
        @brief Verifies a plain-text password against a hashed password.
        @param plain_password The plain-text password to check.
        @param hashed_password The hashed password to verify against.
        @return True if the password matches, False otherwise.
        """
        return cls._context.verify(plain_password, hashed_password)


def create_access_token(user_id: str, email: str, role: str) -> str:
    """
    @brief Generates a signed JWT access token for a user.
    @param user_id The unique ID of the user.
    @param email The user's school email.
    @param role The role assigned to the user.
    @return A string representing the encoded JWT.
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    logger.info("JWT issued for user_id=%s role=%s", user_id, role)
    return token


async def fetch_user_by_email(pool: asyncpg.Pool, email: str) -> asyncpg.Record:
    """
    @brief Query the users table for a record matching the verified school email.
    @param pool The asyncpg connection pool instance used for database operations.
    @param email The school email address to search for (case-insensitive).
    @return asyncpg.Record containing user 'id', 'school_email', 'role', and 'created_at'.
    @throws HTTPException 404 If no user record is found for the specified email.
    """
    query = """
        SELECT id, school_email, role, created_at
        FROM   users
        WHERE  school_email = $1
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, email.lower())

    if row is None:
        logger.warning("No user record found for email=%s", email)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Your school account is not yet registered on the InClass Platform. "
                "Please contact your instructor or platform administrator."
            ),
        )

    logger.info("User found: id=%s role=%s", row["id"], row["role"])
    return row


async def fetch_user_by_id(pool: asyncpg.Pool, user_id: str) -> asyncpg.Record:
    """
    @brief Query the users table for the user id stored in a signed JWT subject.
    @param pool The asyncpg connection pool instance.
    @param user_id The unique identifier of the user as a string.
    @return asyncpg.Record containing user 'id', 'school_email', 'role', and 'created_at'.
    @throws HTTPException 404 If no user record matches the provided user_id.
    """
    query = """
        SELECT id, school_email, role, created_at
        FROM   users
        WHERE  id::text = $1
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, str(user_id))

    if row is None:
        logger.warning("No user record found for id=%s", user_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Your user account is not yet registered on the InClass Platform. "
                "Please contact your instructor or platform administrator."
            ),
        )

    logger.info("User found: id=%s role=%s", row["id"], row["role"])
    return row


async def fetch_registered_student_by_email(
    pool: asyncpg.Pool,
    email: str,
) -> asyncpg.Record:
    """
    @brief Ensure there is an active student record for the verified school email.
    @param pool The asyncpg connection pool instance.
    @param email The school email address of the student.
    @return asyncpg.Record containing student data if found.
    @throws HTTPException 404 If no record with 'student' role matches the email.
    """
    query = """
        SELECT id, school_email, role, created_at
        FROM   users
        WHERE  school_email = $1
          AND  role = 'student'
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, email.lower())

    if row is None:
        logger.warning("Student auth rejected; no student record for email=%s", email)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No registered student account was found for this school email. "
                "Please contact your instructor or platform administrator."
            ),
        )

    logger.info("Student verified: id=%s email=%s", row["id"], row["school_email"])
    return row


async def fetch_registered_instructor_by_email(
    pool: asyncpg.Pool,
    email: str,
) -> asyncpg.Record:
    """
    @brief Ensure there is an instructor record for the provided school email.
    @param pool The asyncpg connection pool instance.
    @param email The school email address of the instructor.
    @return asyncpg.Record containing instructor data if found.
    @throws HTTPException 404 If no record with 'instructor' role matches the email.
    """
    query = """
        SELECT id, school_email, role, created_at
        FROM   users
        WHERE  school_email = $1
          AND  role = 'instructor'
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, email.lower())

    if row is None:
        logger.warning("Instructor auth rejected; no user record for email=%s", email)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No registered instructor account was found for this school email. "
                "Please contact your platform administrator."
            ),
        )

    logger.info("Instructor verified: id=%s email=%s", row["id"], row["school_email"])
    return row


async def fetch_instructor_courses(pool: asyncpg.Pool, instructor_id: str) -> list[asyncpg.Record]:
    """
    @brief Query the database for all courses assigned to a specific instructor.
    @details This join ensures we only return courses mapped to the instructor's ID.
    @param pool The asyncpg connection pool instance.
    @param instructor_id The unique identifier of the instructor.
    @return A list of asyncpg.Record objects representing the assigned courses.
    """
    query = """
        SELECT c.id, c.course_code, c.course_name, c.term, c.created_at
        FROM   courses c
        JOIN   instructor_course_mapping icm ON c.id = icm.course_id
        WHERE  icm.instructor_id::text = $1
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, str(instructor_id))

    logger.info(
        "Instructor courses fetched: instructor_id=%s count=%d", instructor_id, len(rows)
    )
    return rows


async def update_user_password(
    pool: asyncpg.Pool, user_id: str, hashed_password: str
) -> bool:
    """
    @brief Update the password_hash for the user with the specified ID.
    @param pool The asyncpg connection pool instance.
    @param user_id The unique identifier of the user to update.
    @param hashed_password The new bcrypt-hashed password string.
    @return True if the update was successful (one row affected), False otherwise.
    """
    query = """
        UPDATE users
        SET    password_hash = $1,
               updated_at = NOW()
        WHERE  id::text = $2
    """
    async with pool.acquire() as conn:
        status_msg = await conn.execute(query, hashed_password, str(user_id))

    # 'UPDATE 1' indicates exactly one row was modified.
    success = status_msg == "UPDATE 1"
    if success:
        logger.info("Password updated for user_id=%s", user_id)
    else:
        logger.warning("Password update failed or user not found: user_id=%s", user_id)

    return success


async def fetch_password_hash_by_email(pool: asyncpg.Pool, email: str) -> str | None:
    """!
    @brief Retrieve the stored bcrypt hash for a user by their school email.
    @param pool The asyncpg connection pool instance.
    @param email The school email address of the user.
    @return The password hash string if found, otherwise None.
    """
    query = """
        SELECT password_hash
        FROM   users
        WHERE  school_email = $1
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, email.lower())

    if row is None:
        logger.warning("Password hash lookup failed: email=%s", email)
        return None

    return row["password_hash"]


async def instructorLogin(email: str, password: str) -> dict:
    """
    @brief Authenticates an instructor using their email and password.
    @details Verifies the credentials against the stored password hash and issues a JWT.
             The return dictionary matches the expected authentication script structure.
    @param email The school email address of the instructor.
    @param password The plain-text password to verify.
    @return A dictionary containing the authentication status and token details.
    @throws HTTPException 401 If credentials are invalid or password is not set.
    """
    pool = db_pool

    # 1. Fetch instructor
    instructor = await fetch_registered_instructor_by_email(pool, email)

    # 2. Fetch and verify hash
    stored_hash = await fetch_password_hash_by_email(pool, email)
    if not stored_hash or not PasswordHasher.verify(password, stored_hash):
        logger.warning("Login failed: Incorrect password or no password for instructor=%s", email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # 3. Return the response dict the instructor script expects
    access_token = create_access_token(
        user_id=str(instructor["id"]),
        email=instructor["school_email"],
        role=instructor["role"],
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": str(instructor["id"]),
        "role": instructor["role"],
        "email": instructor["school_email"],
    }


async def studentLogin(email: str, password: str) -> dict:
    """
    @brief Authenticates a student using their email and password.
    """
    pool = db_pool
    student = await fetch_registered_student_by_email(pool, email)

    stored_hash = await fetch_password_hash_by_email(pool, email)
    if not stored_hash or not PasswordHasher.verify(password, stored_hash):
        logger.warning("Login failed: Incorrect password for student=%s", email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(
        user_id=str(student["id"]),
        email=student["school_email"],
        role=student["role"],
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": str(student["id"]),
        "role": student["role"],
        "email": student["school_email"],
    }


async def registerStudent(email: str, password: str, full_name: str) -> dict:
    """
    @brief Registers a new student.
    """
    pool = db_pool
    hashed_password = PasswordHasher.hash(password)

    query = """
        INSERT INTO users (school_email, full_name, role, password_hash)
        VALUES ($1, $2, 'student', $3)
        RETURNING id, school_email, role, full_name
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, email.lower(), full_name, hashed_password)
    except UniqueViolationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists."
        )

    access_token = create_access_token(
        user_id=str(row["id"]),
        email=row["school_email"],
        role=row["role"],
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": str(row["id"]),
        "role": row["role"],
        "email": row["school_email"],
        "name": row["full_name"]
    }


async def listMyCourses(email: str, password: str) -> dict:
    """
    @brief Retrieves the courses assigned to an instructor after optional credential validation.
    @details Ensures the instructor is registered before fetching assigned courses.
    @param email The school email address of the instructor.
    @param password The plain-text password (used for grading script fallback).
    @return A dictionary containing a list of assigned courses.
    """
    pool = db_pool

    # 1. Verify credentials (you can call instructorLogin here to validate)
    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)

    # 2. Fetch courses
    courses = await fetch_instructor_courses(pool, str(instructor["id"]))
    return {"courses": [dict(c) for c in courses]}


async def setInstructorPassword(email: str, password: str | None = None) -> dict:
    """
    @brief Allows an instructor to set their initial password.
    @details Hashes the provided plain-text password and stores it in the database.
    @param email The school email address of the instructor.
    @param password The new plain-text password to set, or None to ignore.
    @return A dictionary indicating the status of the password setup.
    @throws HTTPException 500 If the database update fails.
    """
    pool = db_pool

    instructor = await fetch_registered_instructor_by_email(pool, email)

    if not password:
        logger.info("setInstructorPassword: No password provided for user_id=%s", instructor["id"])
        return {"status": "ignored", "message": "No password provided; no changes made."}

    hashed = PasswordHasher.hash(password)
    success = await update_user_password(pool, str(instructor["id"]), hashed)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password.",
        )

    return {"status": "success", "message": "Password set successfully."}


async def changeInstructorPassword(
    email: str, password: str, old_password: str, new_password: str
) -> dict:
    """
    @brief Changes the instructor's password after verifying the existing one.
    @details Ensures the old password matches the stored hash before updating.
    @param email The school email address of the instructor.
    @param password The current password (for grading script compatibility).
    @param old_password The old password to verify.
    @param new_password The new password to set.
    @return A dictionary indicating the result of the password change.
    @throws HTTPException 400 If no existing password is found.
    @throws HTTPException 401 If the old password verification fails.
    @throws HTTPException 500 If the database update fails.
    """
    pool = db_pool

    instructor = await fetch_registered_instructor_by_email(pool, email)
    stored_hash = await fetch_password_hash_by_email(pool, email)

    if not stored_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No existing password found. Use 'set' instead.",
        )

    if not PasswordHasher.verify(old_password, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect existing password.",
        )

    new_hashed = PasswordHasher.hash(new_password)
    success = await update_user_password(pool, str(instructor["id"]), new_hashed)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password.",
        )

    return {"status": "success", "message": "Password changed successfully."}


async def _ensure_instructor_assigned_to_course(
    pool: asyncpg.Pool,
    instructor_id: str,
    course_id: str,
) -> None:
    """
    @brief Validates instructor-course authorization for activity state operations.
    @param pool The asyncpg connection pool instance.
    @param instructor_id The authenticated instructor identifier.
    @param course_id The target course identifier.
    @return None.
    @throws HTTPException 403 If instructor is not assigned to the provided course.
    """
    query = """
        SELECT 1
        FROM   instructor_course_mapping
        WHERE  instructor_id::text = $1
          AND  course_id::text = $2
        LIMIT 1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, str(instructor_id), str(course_id))

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Instructor is not authorized for the target course.",
        )


async def _ensure_student_enrolled_in_course(
    pool: asyncpg.Pool,
    student_id: str,
    course_id: str,
) -> None:
    """Validate that a student belongs to the target course."""
    query = """
        SELECT 1
        FROM   student_course_mapping
        WHERE  student_id::text = $1
          AND  course_id::text = $2
        LIMIT 1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, str(student_id), str(course_id))

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Student is not enrolled in this course.",
        )


def _coerce_objectives_payload(objectives: object) -> list[str]:
    """Return activity objectives as a clean list of strings."""
    raw_objectives = objectives
    if isinstance(raw_objectives, str):
        try:
            raw_objectives = json.loads(raw_objectives)
        except json.JSONDecodeError:
            raw_objectives = [raw_objectives]

    if not isinstance(raw_objectives, list):
        return []

    return [
        objective.strip()
        for objective in raw_objectives
        if isinstance(objective, str) and objective.strip()
    ]


def _meaningful_words(text: str) -> set[str]:
    """
    Normalize text for deterministic objective matching.
    The heuristic lowercases, removes punctuation, splits words, and ignores
    very short/common words so objective-specific terms drive scoring.
    """
    normalized = re.sub(r"[^a-z0-9\s]", " ", (text or "").lower())
    return {
        word
        for word in normalized.split()
        if len(word) > 2 and word not in _AUTO_SCORING_STOP_WORDS
    }


def _objective_is_achieved(objective_words: set[str], matched_words: list[str]) -> bool:
    """Require a simple majority of meaningful objective words to appear."""
    if not objective_words:
        return False

    if len(objective_words) <= 2:
        required_matches = len(objective_words)
    else:
        required_matches = max(2, (len(objective_words) * 3 + 4) // 5)

    return len(matched_words) >= required_matches


def _find_new_objective_achievement(
    objectives: list[str],
    answer: str,
    earned_indexes: set[int],
) -> tuple[int, str, list[str]] | None:
    """Find the first achieved objective that has not already earned a point."""
    answer_words = _meaningful_words(answer)

    for objective_index, objective_text in enumerate(objectives):
        objective_words = _meaningful_words(objective_text)
        matched_words = sorted(objective_words & answer_words)
        if (
            objective_index not in earned_indexes
            and _objective_is_achieved(objective_words, matched_words)
        ):
            return objective_index, objective_text, matched_words

    return None


def _build_objective_mini_lesson(objective_text: str, matched_words: list[str]) -> str:
    """Create a short academic note only after a new objective earns credit."""
    if matched_words:
        focus = ", ".join(matched_words[:3])
        return (
            f"Mini-lesson: {objective_text} depends on using key ideas like "
            f"{focus} in a clear explanation, example, or cause-and-effect link."
        )

    return (
        f"Mini-lesson: {objective_text} is strongest when the answer states the "
        "main idea clearly and supports it with one precise academic detail."
    )


def _next_objective_question(objective_text: str) -> str:
    """Ask a single guidance question that steers toward the next objective."""
    _ = objective_text  # Objective is selected internally; prompt should not reveal answers directly.
    return (
        "What is one precise academic detail you can add next to strengthen your answer "
        "for this activity objective?"
    )


async def _fetch_activity_status(
    pool: asyncpg.Pool,
    course_id: str,
    activity_no: int,
) -> str:
    """
    @brief Retrieves the current status of a course activity by course_id and activity_no.
    @param pool The asyncpg connection pool instance.
    @param course_id The target course identifier.
    @param activity_no The activity number unique within the course.
    @return The current activity status value.
    @throws HTTPException 404 If no matching activity exists.
    """
    query = """
        SELECT status
        FROM   activities
        WHERE  course_id::text = $1
          AND  activity_no = $2
        LIMIT 1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, str(course_id), int(activity_no))

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Activity not found for the specified course and activity number.",
        )

    return str(row["status"])


def _normalize_objectives(objectives: list[str]) -> list[str]:
    """
    @brief Validates and normalizes objective text values.
    @param objectives Raw objective list from API payload.
    @return A trimmed list of objectives.
    @throws HTTPException 400 If list is empty or contains blank values.
    """
    normalized = [o.strip() for o in objectives if isinstance(o, str)]
    if not normalized or any(not o for o in normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one non-empty objective is required.",
        )

    return normalized


def _build_activity_title(activity_text: str, optional_title: Optional[str]) -> str:
    """
    @brief Produces a non-empty title for activities table compatibility.
    @param activity_text Main activity text.
    @param optional_title Optional explicit title from API payload.
    @return A non-empty title string with max 120 chars.
    """
    if optional_title and optional_title.strip():
        return optional_title.strip()[:120]

    compact_text = " ".join(activity_text.strip().split())
    return compact_text[:120] if compact_text else "Untitled Activity"


async def create_activity(
    pool: asyncpg.Pool,
    instructor_id: str,
    course_id: str,
    activity_no: int,
    activity_text: str,
    objectives: list[str],
    title: Optional[str] = None,
) -> dict:
    """
    @brief Creates a new activity for an authorized instructor (US-F).
    @param pool The asyncpg connection pool instance.
    @param instructor_id Authenticated instructor ID.
    @param course_id Target course ID.
    @param activity_no Activity number unique within the course.
    @param activity_text Core activity text shown to students.
    @param objectives Objective list stored for tutoring/scoring flows.
    @param title Optional activity title.
    @return A dictionary containing created activity metadata.
    @throws HTTPException 400 For invalid required fields.
    @throws HTTPException 403 If instructor is not assigned to the course.
    @throws HTTPException 409 For duplicate activity number in same course.
    """
    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)

    if activity_no < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="activity_no must be greater than or equal to 1.",
        )

    clean_text = activity_text.strip()
    if not clean_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="activity_text is required.",
        )

    clean_objectives = _normalize_objectives(objectives)
    final_title = _build_activity_title(clean_text, title)

    query = """
        INSERT INTO activities (
            course_id,
            activity_no,
            title,
            description,
            objectives,
            created_by,
            status
        )
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, 'DRAFT')
        RETURNING id, course_id, activity_no, title, description, objectives, status
    """

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                query,
                str(course_id),
                int(activity_no),
                final_title,
                clean_text,
                clean_objectives,
                str(instructor_id),
            )
    except UniqueViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An activity with this activity_no already exists in the selected course.",
        ) from exc

    return {
        "status": "success",
        "activity_id": str(row["id"]),
        "course_id": str(row["course_id"]),
        "activity_no": int(row["activity_no"]),
        "title": row["title"],
        "activity_text": row["description"],
        "objectives": row["objectives"],
        "activity_status": row["status"],
    }


async def start_activity(
    pool: asyncpg.Pool,
    instructor_id: str,
    course_id: str,
    activity_no: int,
) -> dict:
    """
    @brief Transitions an activity from DRAFT to ACTIVE for an authorized instructor.
    @param pool The asyncpg connection pool instance.
    @param instructor_id The authenticated instructor identifier.
    @param course_id The target course identifier.
    @param activity_no The activity number unique within the course.
    @return A dictionary containing operation status and resulting activity state.
    @throws HTTPException 403 If instructor is not assigned to the target course.
    @throws HTTPException 404 If activity does not exist.
    @throws HTTPException 409 If the current activity state is not DRAFT.
    """
    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)
    current_status = await _fetch_activity_status(pool, course_id, activity_no)

    if current_status != "DRAFT":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Invalid activity transition. "
                "Only DRAFT activities can be started."
            ),
        )

    query = """
        UPDATE activities
        SET    status = 'ACTIVE',
               starts_at = NOW()
        WHERE  course_id::text = $1
          AND  activity_no = $2
    """
    async with pool.acquire() as conn:
        status_msg = await conn.execute(query, str(course_id), int(activity_no))

    if status_msg != "UPDATE 1":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Activity not found for the specified course and activity number.",
        )

    return {
        "status": "success",
        "course_id": str(course_id),
        "activity_no": int(activity_no),
        "activity_status": "ACTIVE",
    }


async def end_activity(
    pool: asyncpg.Pool,
    instructor_id: str,
    course_id: str,
    activity_no: int,
) -> dict:
    """
    @brief Transitions an activity from ACTIVE to ENDED for an authorized instructor.
    @param pool The asyncpg connection pool instance.
    @param instructor_id The authenticated instructor identifier.
    @param course_id The target course identifier.
    @param activity_no The activity number unique within the course.
    @return A dictionary containing operation status and resulting activity state.
    @throws HTTPException 403 If instructor is not assigned to the target course.
    @throws HTTPException 404 If activity does not exist.
    @throws HTTPException 409 If the current activity state is not ACTIVE.
    """
    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)
    current_status = await _fetch_activity_status(pool, course_id, activity_no)

    if current_status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Invalid activity transition. "
                "Only ACTIVE activities can be ended."
            ),
        )

    query = """
        UPDATE activities
        SET    status = 'ENDED'
        WHERE  course_id::text = $1
          AND  activity_no = $2
    """
    async with pool.acquire() as conn:
        status_msg = await conn.execute(query, str(course_id), int(activity_no))

    if status_msg != "UPDATE 1":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Activity not found for the specified course and activity number.",
        )

    return {
        "status": "success",
        "course_id": str(course_id),
        "activity_no": int(activity_no),
        "activity_status": "ENDED",
    }


async def startActivity(
    email: str,
    password: str,
    course_id: str,
    activity_no: int,
) -> dict:
    """
    @brief Starts an activity by transitioning state from DRAFT to ACTIVE.
    @details Exact signature required by Phase 1 API Contract.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    return await start_activity(
        pool=pool,
        instructor_id=instructor_id,
        course_id=course_id,
        activity_no=activity_no,
    )


async def createActivity(
    email: str,
    password: str,
    course_id: str,
    activity_no: int,
    activity_text: str,
    objectives: list[str],
    title: Optional[str] = None,
) -> dict:
    """
    @brief Creates an activity with US-F contract-compatible signature.
    @details Validates instructor credentials (fallback mode) and authorization.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    return await create_activity(
        pool=pool,
        instructor_id=instructor_id,
        course_id=course_id,
        activity_no=activity_no,
        activity_text=activity_text,
        objectives=objectives,
        title=title,
    )


async def endActivity(
    email: str,
    password: str,
    course_id: str,
    activity_no: int,
) -> dict:
    """
    @brief Ends an activity by transitioning state from ACTIVE to ENDED.
    @details Exact signature required by Phase 1 API Contract.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    return await end_activity(
        pool=pool,
        instructor_id=instructor_id,
        course_id=course_id,
        activity_no=activity_no,
    )


async def submitAnswer(
    email: str,
    password: str,
    course_id: str,
    activity_no: int,
    answer: str,
) -> dict:
    """
    @brief Scores a student answer by awarding +1 for a newly achieved objective.
    @details Signature is grading-script-compatible; password is accepted but the
             endpoint authenticates the student before this service is called.
    """
    pool = db_pool
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database pool is not initialized.",
        )

    student = await fetch_registered_student_by_email(pool, email)
    student_id = str(student["id"])
    await _ensure_student_enrolled_in_course(pool, student_id, course_id)

    clean_answer = (answer or "").strip()
    async with pool.acquire() as conn:
        async with conn.transaction():
            activity = await conn.fetchrow(
                """
                SELECT id, course_id, activity_no, objectives, status
                FROM   activities
                WHERE  course_id::text = $1
                  AND  activity_no = $2
                LIMIT 1
                FOR UPDATE
                """,
                str(course_id),
                int(activity_no),
            )

            if activity is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Activity not found.",
                )

            activity_status = str(activity["status"])
            if activity_status != "ACTIVE":
                detail = "Only ACTIVE activities accept student answers."
                if activity_status == "ENDED":
                    detail = "This activity is ENDED, so the tutoring flow cannot continue."
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=detail,
                )

            objectives = _coerce_objectives_payload(activity["objectives"])
            earned_rows = await conn.fetch(
                """
                SELECT objective_index
                FROM   objective_score_logs
                WHERE  student_id = $1
                  AND  activity_id = $2
                ORDER BY objective_index
                """,
                student["id"],
                activity["id"],
            )
            earned_indexes = {int(row["objective_index"]) for row in earned_rows}
            current_score = len(earned_indexes)

            if not objectives or current_score >= len(objectives):
                await _upsert_student_activity_progress(
                    conn=conn,
                    student_id=str(student["id"]),
                    course_id=str(activity["course_id"]),
                    activity_id=str(activity["id"]),
                    current_score=current_score,
                    completed=True,
                    last_question=None,
                    last_answer=clean_answer,
                )
                return {
                    "score_delta": 0,
                    "score": current_score,
                    "message": (
                        "Excellent work, all objectives are covered. "
                        f"Your score is {current_score}."
                    ),
                    "completed": True,
                    "next_question": None,
                }

            achievement = _find_new_objective_achievement(
                objectives=objectives,
                answer=clean_answer,
                earned_indexes=earned_indexes,
            )

            if achievement is None:
                next_unearned_index = next(
                    (index for index in range(len(objectives)) if index not in earned_indexes),
                    None,
                )
                next_question = (
                    _next_objective_question(objectives[next_unearned_index])
                    if next_unearned_index is not None
                    else None
                )
                await _upsert_student_activity_progress(
                    conn=conn,
                    student_id=str(student["id"]),
                    course_id=str(activity["course_id"]),
                    activity_id=str(activity["id"]),
                    current_score=current_score,
                    completed=False,
                    last_question=next_question,
                    last_answer=clean_answer,
                )
                return {
                    "score_delta": 0,
                    "score": current_score,
                    "message": (
                        "No new objective was scored yet. Keep trying with a "
                        "more specific academic detail."
                    ),
                    "completed": False,
                    "next_question": next_question,
                }

            objective_index, objective_text, matched_words = achievement
            total_score = current_score + 1
            metadata = {
                "answer": clean_answer,
                "matched_words": matched_words,
                "grading_type": "auto",
            }
            inserted = await conn.fetchrow(
                """
                INSERT INTO objective_score_logs (
                    student_id,
                    course_id,
                    activity_id,
                    objective_index,
                    objective_text,
                    score_delta,
                    total_score,
                    metadata
                )
                VALUES ($1, $2, $3, $4, $5, 1, $6, $7::jsonb)
                ON CONFLICT (student_id, activity_id, objective_index)
                DO NOTHING
                RETURNING total_score
                """,
                student["id"],
                activity["course_id"],
                activity["id"],
                int(objective_index),
                objective_text,
                int(total_score),
                json.dumps(metadata),
            )

            if inserted is None:
                latest_earned_rows = await conn.fetch(
                    """
                    SELECT objective_index
                    FROM   objective_score_logs
                    WHERE  student_id = $1
                      AND  activity_id = $2
                    ORDER BY objective_index
                    """,
                    student["id"],
                    activity["id"],
                )
                latest_earned_indexes = {
                    int(row["objective_index"]) for row in latest_earned_rows
                }
                latest_score = len(latest_earned_indexes)
                next_unearned_index = next(
                    (
                        index
                        for index in range(len(objectives))
                        if index not in latest_earned_indexes
                    ),
                    None,
                )
                next_question = (
                    _next_objective_question(objectives[next_unearned_index])
                    if next_unearned_index is not None
                    else None
                )
                completed = latest_score >= len(objectives)
                await _upsert_student_activity_progress(
                    conn=conn,
                    student_id=str(student["id"]),
                    course_id=str(activity["course_id"]),
                    activity_id=str(activity["id"]),
                    current_score=latest_score,
                    completed=completed,
                    last_question=None if completed else next_question,
                    last_answer=clean_answer,
                )
                return {
                    "score_delta": 0,
                    "score": latest_score,
                    "message": (
                        "Excellent work, all objectives are covered. Your score did not change."
                        if completed
                        else (
                            "That objective was already counted, so your score did "
                            "not change. Keep going with another specific idea."
                        )
                    ),
                    "completed": completed,
                    "next_question": None if completed else next_question,
                }

            total_score = int(inserted["total_score"])
            await conn.execute(
                """
                INSERT INTO activity_scores (
                    activity_id,
                    student_id,
                    score,
                    grading_type,
                    note
                )
                VALUES ($1, $2, $3, 'auto', 'Objective-based automatic score')
                ON CONFLICT (activity_id, student_id)
                DO UPDATE SET
                    score = EXCLUDED.score,
                    grading_type = 'auto',
                    note = EXCLUDED.note,
                    updated_at = NOW()
                WHERE activity_scores.grading_type = 'auto'
                """,
                activity["id"],
                student["id"],
                total_score,
            )

            updated_earned_indexes = set(earned_indexes)
            updated_earned_indexes.add(int(objective_index))
            next_unearned_index = next(
                (
                    index
                    for index in range(len(objectives))
                    if index not in updated_earned_indexes
                ),
                None,
            )
            next_question = (
                _next_objective_question(objectives[next_unearned_index])
                if next_unearned_index is not None
                else None
            )
            completed = total_score >= len(objectives)
            response = {
                "score_delta": 1,
                "score": total_score,
                "achieved_objective": objective_text,
                "mini_lesson": _build_objective_mini_lesson(
                    objective_text,
                    matched_words,
                ),
                "message": (
                    "Great work, you earned +1 point. "
                    f"Your score is now {total_score}."
                ),
                "completed": completed,
                "next_question": None if completed else next_question,
            }

            if completed:
                response["message"] = (
                    "Excellent work, you covered all objectives. "
                    f"Your final objective score is {total_score}."
                )

            await _upsert_student_activity_progress(
                conn=conn,
                student_id=str(student["id"]),
                course_id=str(activity["course_id"]),
                activity_id=str(activity["id"]),
                current_score=total_score,
                completed=completed,
                last_question=None if completed else next_question,
                last_answer=clean_answer,
            )

            return response

async def updateActivity(
    email: str, 
    password: str, 
    course_id: str, 
    activity_no: int, 
    activity_text: str | None = None, 
    objectives: list[str] | None = None, 
    title: str | None = None
) -> dict:
    """
    @brief Updates allowed fields of an activity (US-G).
    @details Exact signature required by Phase 1 API Contract.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)

    # Criteria: Empty patch is rejected
    if activity_text is None and objectives is None and title is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Empty patch: At least one allowed field must be provided."
        )

    # Build dynamic update query to only update provided fields
    updates = []
    values = [course_id, activity_no]
    idx = 3

    if activity_text is not None:
        updates.append(f"description = ${idx}")
        values.append(activity_text.strip())
        idx += 1

    if objectives is not None:
        clean_objectives = _normalize_objectives(objectives)
        updates.append(f"objectives = ${idx}::jsonb")
        values.append(json.dumps(clean_objectives))
        idx += 1

    if title is not None:
        updates.append(f"title = ${idx}")
        clean_title = title.strip()[:120] if title.strip() else "Untitled Activity"
        values.append(clean_title)
        idx += 1

    set_clause = ", ".join(updates)
    query = f"""
        UPDATE activities
        SET {set_clause}, updated_at = NOW()
        WHERE course_id::text = $1 AND activity_no = $2
        RETURNING id
    """

    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, *values)

    # Criteria: Non-existent activity returns a clear error
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Activity not found.")

    return {
        "status": "success",
        "message": f"Activity {activity_no} updated successfully."
    }


async def submitManualGrade(
    email: str, 
    password: str, 
    course_id: str, 
    activity_no: int, 
    student_email: str, 
    score: float, 
    note: str = ""
) -> dict:
    """
    @brief Submits a manual grade for a student in a specific activity (US-L).
    @details Exact signature required by Phase 1 API Contract.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    # Criteria: Unauthorized instructor cannot submit manual grade
    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)

    # Verify activity exists
    activity_query = "SELECT id, max_score, status FROM activities WHERE course_id::text = $1 AND activity_no = $2"
    async with pool.acquire() as conn:
        activity = await conn.fetchrow(activity_query, course_id, activity_no)

    if not activity:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Activity not found.")

    if activity["status"] == "ENDED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Cannot submit manual grades for an ended or reset activity."
        )

    # Verify student exists
    student = await fetch_registered_student_by_email(pool, student_email)

    # Optional but recommended: Verify student is enrolled in the course
    enrolled_query = "SELECT 1 FROM student_course_mapping WHERE student_id = $1 AND course_id::text = $2"
    async with pool.acquire() as conn:
        is_enrolled = await conn.fetchrow(enrolled_query, student["id"], course_id)
        if not is_enrolled:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Student is not enrolled in this course.")

    # Criteria: Validate score limits
    if score < 0 or score > activity["max_score"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Score must be between 0 and the activity maximum ({activity['max_score']})."
        )

    # Criteria: Log manual grading event (upsert behavior)
    upsert_query = """
        INSERT INTO activity_scores (activity_id, student_id, score, grading_type, note)
        VALUES ($1, $2, $3, 'manual', $4)
        ON CONFLICT (activity_id, student_id)
        DO UPDATE SET 
            score = EXCLUDED.score, 
            grading_type = 'manual', 
            note = EXCLUDED.note, 
            updated_at = NOW()
    """
    async with pool.acquire() as conn:
        await conn.execute(upsert_query, activity["id"], student["id"], score, note)

    return {
        "status": "success",
        "message": f"Manual grade of {score} successfully logged for {student_email}."
    }


async def listActivityLogs(email: str, password: str, activity_id: str) -> dict:
    """
    @brief Lists score and objective events for one activity.
    @details The requesting instructor must be assigned to the activity course.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)

    async with pool.acquire() as conn:
        activity = await conn.fetchrow(
            """
            SELECT a.id, a.course_id
            FROM   activities a
            JOIN   instructor_course_mapping icm
                   ON icm.course_id = a.course_id
                  AND icm.instructor_id = $2
            WHERE  a.id::text = $1
            LIMIT  1
            """,
            str(activity_id),
            instructor["id"],
        )

        if activity is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Activity not found or not available for this instructor.",
            )

        rows = await conn.fetch(
            """
            SELECT *
            FROM (
                SELECT
                    osl.id::text AS id,
                    osl.activity_id::text AS activity_id,
                    COALESCE(u.full_name, u.school_email) AS student_name,
                    u.school_email AS student_email,
                    osl.total_score::float AS score,
                    jsonb_build_object(
                        'objective_index', osl.objective_index,
                        'objective_text', osl.objective_text,
                        'score_delta', osl.score_delta,
                        'answer', osl.metadata ->> 'answer',
                        'matched_words', osl.metadata -> 'matched_words',
                        'grading_type', osl.metadata ->> 'grading_type'
                    ) AS objective_metadata,
                    'OBJECTIVE_SCORE' AS event_type,
                    osl.created_at AS event_timestamp
                FROM objective_score_logs osl
                JOIN users u ON u.id = osl.student_id
                WHERE osl.activity_id = $1

                UNION ALL

                SELECT
                    score.id::text AS id,
                    score.activity_id::text AS activity_id,
                    COALESCE(u.full_name, u.school_email) AS student_name,
                    u.school_email AS student_email,
                    score.score::float AS score,
                    jsonb_build_object(
                        'grading_type', score.grading_type,
                        'note', score.note
                    ) AS objective_metadata,
                    CASE
                        WHEN score.grading_type = 'manual' THEN 'MANUAL_GRADE'
                        ELSE 'AUTO_SCORE'
                    END AS event_type,
                    score.updated_at AS event_timestamp
                FROM activity_scores score
                JOIN users u ON u.id = score.student_id
                WHERE score.activity_id = $1
            ) AS activity_logs
            ORDER BY event_timestamp DESC
            """,
            activity["id"],
        )

    logs = []
    for row in rows:
        timestamp = row["event_timestamp"]
        logs.append(
            {
                "id": row["id"],
                "activityId": row["activity_id"],
                "studentName": row["student_name"],
                "studentEmail": row["student_email"],
                "score": row["score"],
                "objectiveMetadata": row["objective_metadata"],
                "timestamp": timestamp.isoformat() if timestamp else None,
                "eventType": row["event_type"],
            }
        )

    return {"logs": logs}


async def _upsert_student_activity_progress(
    conn: asyncpg.Connection,
    student_id: str,
    course_id: str,
    activity_id: str,
    current_score: int,
    completed: bool,
    last_question: str | None,
    last_answer: str | None,
) -> None:
    """Persist the current tutoring state for a student on a specific activity."""
    await conn.execute(
        """
        INSERT INTO student_activity_progress (
            student_id,
            course_id,
            activity_id,
            current_score,
            completed,
            last_question,
            last_answer,
            last_interaction_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        ON CONFLICT (student_id, activity_id)
        DO UPDATE SET
            course_id = EXCLUDED.course_id,
            current_score = EXCLUDED.current_score,
            completed = EXCLUDED.completed,
            last_question = EXCLUDED.last_question,
            last_answer = EXCLUDED.last_answer,
            last_interaction_at = NOW(),
            updated_at = NOW()
        """,
        student_id,
        course_id,
        activity_id,
        int(current_score),
        bool(completed),
        last_question,
        last_answer,
    )


async def getStudentActivity(
    email: str, password: str, course_id: str, activity_no: int
) -> dict:
    """
    @brief Returns the activity content and first guidance question for students.
    """
    pool = db_pool
    student = await fetch_registered_student_by_email(pool, email)
    await _ensure_student_enrolled_in_course(pool, str(student["id"]), course_id)
    activity = await pool.fetchrow(
        """
        SELECT id, title, description, objectives, status
        FROM activities
        WHERE course_id::text = $1
          AND activity_no = $2
        LIMIT 1
        """,
        course_id,
        activity_no,
    )
    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found.")

    activity_status = str(activity["status"])
    if activity_status != "ACTIVE":
        detail = "Only ACTIVE activities can be opened."
        if activity_status == "ENDED":
            detail = "This activity is ENDED, so the tutoring flow cannot continue."
        raise HTTPException(status_code=403, detail=detail)

    objectives = _coerce_objectives_payload(activity["objectives"])
    earned_rows = await pool.fetch(
        """
        SELECT objective_index
        FROM objective_score_logs
        WHERE student_id = $1
          AND activity_id = $2
        ORDER BY objective_index
        """,
        student["id"],
        activity["id"],
    )
    earned_indexes = {int(row["objective_index"]) for row in earned_rows}
    current_score = len(earned_indexes)

    next_unearned_index = next(
        (index for index in range(len(objectives)) if index not in earned_indexes),
        None,
    )
    completed = bool(objectives) and current_score >= len(objectives)
    next_question = (
        _next_objective_question(objectives[next_unearned_index])
        if next_unearned_index is not None
        else None
    )

    # US-J: the first tutoring response includes activity text and exactly one question.
    if not objectives:
        next_question = (
            "What is one clear, objective-focused explanation you can provide for this activity?"
        )

    async with pool.acquire() as conn:
        await _upsert_student_activity_progress(
            conn=conn,
            student_id=str(student["id"]),
            course_id=str(course_id),
            activity_id=str(activity["id"]),
            current_score=current_score,
            completed=completed,
            last_question=next_question,
            last_answer=None,
        )

    return {
        "title": activity["title"],
        "activity_text": activity["description"],
        "status": activity_status,
        "score": current_score,
        "completed": completed,
        "next_question": next_question if not completed else None,
    }
async def resetActivity(
    email: str, password: str, course_id: str, activity_no: int
) -> dict:
    """
    @brief Resets an activity and deletes scores (US-M).
    """
    pool = db_pool
    if password: await instructorLogin(email, password)
    instructor = await fetch_registered_instructor_by_email(pool, email)
    await _ensure_instructor_assigned_to_course(pool, str(instructor["id"]), course_id)
    async with pool.acquire() as conn:
        async with conn.transaction():
            activity = await conn.fetchrow("SELECT id FROM activities WHERE course_id::text = $1 AND activity_no = $2 FOR UPDATE", course_id, activity_no)
            if not activity: raise HTTPException(404, detail="Not found.")
            await conn.execute("DELETE FROM objective_score_logs WHERE activity_id = $1", activity["id"])
            await conn.execute("DELETE FROM activity_scores WHERE activity_id = $1", activity["id"])
            await conn.execute("DELETE FROM student_activity_progress WHERE activity_id = $1", activity["id"])
            await conn.execute("UPDATE activities SET status = 'ENDED' WHERE id = $1", activity["id"])
    return {"status": "success", "message": "Activity reset."}
async def listActivities(
    email: str, password: str, course_id: str
) -> dict:
    """
    @brief Lists activities in a selected course (US-E).
    """
    pool = db_pool
    if password: await instructorLogin(email, password)
    instructor = await fetch_registered_instructor_by_email(pool, email)
    await _ensure_instructor_assigned_to_course(pool, str(instructor["id"]), course_id)
    rows = await pool.fetch(
        """
        SELECT id, activity_no, title, description, objectives, status
        FROM activities
        WHERE course_id::text = $1
        ORDER BY activity_no ASC
        """,
        course_id,
    )
    activities = [
        {
            "activity_id": str(r["id"]),
            "course_id": str(course_id),
            "activity_no": r["activity_no"],
            "title": r["title"],
            "activity_text": r["description"],
            "objectives": _coerce_objectives_payload(r["objectives"]),
            "status": r["status"],
        }
        for r in rows
    ]
    return {"activities": activities}
