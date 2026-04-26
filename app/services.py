import logging

import asyncpg
from fastapi import HTTPException, status

logger = logging.getLogger("inclass.auth")


async def fetch_user_by_email(pool: asyncpg.Pool, email: str) -> asyncpg.Record:
    """
    Query the users table for a record matching the verified school email.
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


async def fetch_registered_student_by_email(
    pool: asyncpg.Pool,
    email: str,
) -> asyncpg.Record:
    """
    Ensure there is an active student record for the verified school email.
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
