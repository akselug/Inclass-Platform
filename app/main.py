import logging
import os
from datetime import datetime, timedelta, timezone

import asyncpg
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from jose import JWTError, jwt
from pydantic import BaseModel

from app.services import fetch_registered_student_by_email, fetch_user_by_email

load_dotenv()

GOOGLE_CLIENT_ID: str = os.environ["GOOGLE_CLIENT_ID"]
SCHOOL_EMAIL_DOMAIN: str = os.environ["SCHOOL_EMAIL_DOMAIN"]
DATABASE_URL: str = os.environ["DATABASE_URL"]
JWT_SECRET: str = os.environ["JWT_SECRET"]
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("inclass.auth")

app = FastAPI(
    title="InClass Auth Service",
    description="Google Federated Sign-In with role-based access",
    version="1.0.0",
)


@app.on_event("startup")
async def startup() -> None:
    app.state.db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    logger.info("Database connection pool created.")


@app.on_event("shutdown")
async def shutdown() -> None:
    await app.state.db_pool.close()
    logger.info("Database connection pool closed.")


class GoogleTokenRequest(BaseModel):
    id_token: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str
    email: str


def verify_google_id_token(raw_token: str) -> dict:
    try:
        claims = google_id_token.verify_oauth2_token(
            raw_token,
            google_requests.Request(),
            audience=GOOGLE_CLIENT_ID,
        )
        logger.info("Google token verified for sub=%s", claims.get("sub"))
        return claims
    except ValueError as exc:
        logger.warning("Google token verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Google ID token.",
        ) from exc


def enforce_school_email(email: str) -> None:
    if not email.lower().endswith(f"@{SCHOOL_EMAIL_DOMAIN.lower()}"):
        logger.warning("Non-school email rejected: %s", email)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access is restricted to @{SCHOOL_EMAIL_DOMAIN} addresses. "
                f"Please sign in with your school account."
            ),
        )


def create_access_token(user_id: str, email: str, role: str) -> str:
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


@app.post(
    "/auth/google",
    response_model=AuthResponse,
    summary="Google Federated Sign-In",
    tags=["Authentication"],
)
async def google_sign_in(body: GoogleTokenRequest) -> AuthResponse:
    claims = verify_google_id_token(body.id_token)
    email: str = claims.get("email", "")

    enforce_school_email(email)
    user = await fetch_user_by_email(app.state.db_pool, email)

    access_token = create_access_token(
        user_id=str(user["id"]),
        email=user["school_email"],
        role=user["role"],
    )

    return AuthResponse(
        access_token=access_token,
        user_id=str(user["id"]),
        role=user["role"],
        email=user["school_email"],
    )


@app.post(
    "/auth/google/student",
    response_model=AuthResponse,
    summary="Google Sign-In (Student)",
    tags=["Authentication"],
)
async def google_student_sign_in(body: GoogleTokenRequest) -> AuthResponse:
    claims = verify_google_id_token(body.id_token)
    email: str = claims.get("email", "")

    enforce_school_email(email)
    student = await fetch_registered_student_by_email(app.state.db_pool, email)

    access_token = create_access_token(
        user_id=str(student["id"]),
        email=student["school_email"],
        role=student["role"],
    )

    return AuthResponse(
        access_token=access_token,
        user_id=str(student["id"]),
        role=student["role"],
        email=student["school_email"],
    )


bearer_scheme = HTTPBearer()


def decode_access_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token is invalid or has expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@app.get(
    "/auth/me",
    summary="Current user identity",
    tags=["Authentication"],
)
async def get_current_user(payload: dict = Depends(decode_access_token)) -> dict:
    return {
        "user_id": payload["sub"],
        "email": payload["email"],
        "role": payload["role"],
    }


@app.get(
    "/health/db",
    summary="Database health check",
    tags=["Health"],
)
async def db_health() -> dict:
    async with app.state.db_pool.acquire() as conn:
        ok = await conn.fetchval("SELECT 1")
    return {"database": "ok" if ok == 1 else "unexpected"}


@app.get(
    "/auth/google/student/test",
    response_class=HTMLResponse,
    summary="Google student sign-in test page",
    tags=["Authentication"],
)
def google_student_sign_in_test_page() -> HTMLResponse:
    html = f"""
<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>InClass Student Google Sign-In Test</title>
    <script src=\"https://accounts.google.com/gsi/client\" async defer></script>
    <style>
        body {{
            font-family: Segoe UI, Arial, sans-serif;
            max-width: 760px;
            margin: 40px auto;
            padding: 0 16px;
            line-height: 1.45;
        }}
        .panel {{
            border: 1px solid #d9d9d9;
            border-radius: 10px;
            padding: 16px;
            margin-top: 16px;
            background: #fafafa;
        }}
        pre {{
            white-space: pre-wrap;
            word-break: break-word;
            background: #0f172a;
            color: #e2e8f0;
            border-radius: 8px;
            padding: 12px;
            min-height: 84px;
        }}
    </style>
</head>
<body>
    <h1>Student Google Sign-In Test</h1>
    <p>Use your school Google account. This page sends the Google ID token to <strong>/auth/google/student</strong>.</p>

    <div class=\"panel\">
        <div id=\"g_id_onload\"
                 data-client_id=\"{GOOGLE_CLIENT_ID}\"
                 data-callback=\"handleCredentialResponse\"
                 data-auto_prompt=\"false\">
        </div>
        <div class=\"g_id_signin\"
                 data-type=\"standard\"
                 data-size=\"large\"
                 data-theme=\"outline\"
                 data-text=\"signin_with\"
                 data-shape=\"pill\"
                 data-logo_alignment=\"left\">
        </div>
    </div>

    <div class=\"panel\">
        <h3>Backend Response</h3>
        <pre id=\"result\">Waiting for sign-in...</pre>
    </div>

    <script>
        async function handleCredentialResponse(response) {{
            const resultEl = document.getElementById('result');
            resultEl.textContent = 'Google token received. Calling backend...';

            try {{
                const apiResponse = await fetch('/auth/google/student', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ id_token: response.credential }})
                }});

                const data = await apiResponse.json();
                resultEl.textContent = JSON.stringify({{
                    status: apiResponse.status,
                    ok: apiResponse.ok,
                    data: data
                }}, null, 2);
            }} catch (error) {{
                resultEl.textContent = 'Request failed: ' + String(error);
            }}
        }}
        window.handleCredentialResponse = handleCredentialResponse;
    </script>
</body>
</html>
"""
    return HTMLResponse(content=html)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
