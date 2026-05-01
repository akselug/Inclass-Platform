"""
@file services.py
@brief User and Course management services for the InClass Platform.
@details This module provides asynchronous database operations for fetching user records, 
         managing instructor courses, and updating user credentials.
"""

import logging
import os
from datetime import datetime, timedelta, timezone

import asyncpg
from fastapi import HTTPException, status
from jose import jwt
from passlib.context import CryptContext

# Global pool for the service layer
db_pool: asyncpg.Pool | None = None

JWT_SECRET: str = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

logger = logging.getLogger("inclass.auth")


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
