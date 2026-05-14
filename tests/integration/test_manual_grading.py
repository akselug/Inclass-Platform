"""
@file test_manual_grading.py
@brief Integration tests for POST /instructor/activity/{course_id}/{activity_no}/grade/manual.
@details Validates that manual grades are persisted for authorized instructors
         and rejected for unauthorized ones.
"""

import pytest
from unittest.mock import AsyncMock, patch

from tests.conftest import COURSE_ID

pytestmark = pytest.mark.integration


class TestManualGrading:
    """POST .../grade/manual endpoint behavior."""

    async def test_manual_grade_returns_success(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Authorized instructor can submit a manual grade."""
        fake_result = {
            "status": "success",
            "message": "Manual grade of 85.0 successfully logged for student@mef.edu.tr.",
        }
        with patch(
            "app.main.submitManualGrade", new_callable=AsyncMock
        ) as mock_grade:
            mock_grade.return_value = fake_result

            resp = await async_client.post(
                f"/instructor/activity/{COURSE_ID}/1/grade/manual",
                json={
                    "student_email": "student@mef.edu.tr",
                    "score": 85.0,
                    "note": "Good work",
                },
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        assert "85.0" in body["message"]

    async def test_manual_grade_rejected_for_unauthorized(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Instructor not assigned to the course gets 403."""
        from fastapi import HTTPException

        with patch(
            "app.main.submitManualGrade", new_callable=AsyncMock
        ) as mock_grade:
            mock_grade.side_effect = HTTPException(
                status_code=403,
                detail="Instructor is not authorized for the target course.",
            )

            resp = await async_client.post(
                f"/instructor/activity/{COURSE_ID}/1/grade/manual",
                json={
                    "student_email": "student@mef.edu.tr",
                    "score": 90.0,
                },
            )

        assert resp.status_code == 403

    async def test_manual_grade_404_nonexistent_activity(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Grading a nonexistent activity returns 404."""
        from fastapi import HTTPException

        with patch(
            "app.main.submitManualGrade", new_callable=AsyncMock
        ) as mock_grade:
            mock_grade.side_effect = HTTPException(
                status_code=404, detail="Activity not found."
            )

            resp = await async_client.post(
                f"/instructor/activity/{COURSE_ID}/999/grade/manual",
                json={
                    "student_email": "student@mef.edu.tr",
                    "score": 70.0,
                },
            )

        assert resp.status_code == 404

    async def test_manual_grade_400_invalid_score(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Score exceeding max_score returns 400."""
        from fastapi import HTTPException

        with patch(
            "app.main.submitManualGrade", new_callable=AsyncMock
        ) as mock_grade:
            mock_grade.side_effect = HTTPException(
                status_code=400,
                detail="Score must be between 0 and the activity maximum (100).",
            )

            resp = await async_client.post(
                f"/instructor/activity/{COURSE_ID}/1/grade/manual",
                json={
                    "student_email": "student@mef.edu.tr",
                    "score": 150.0,
                },
            )

        assert resp.status_code == 400

    async def test_manual_grade_401_without_auth(self, async_client, mock_db_pool):
        """Unauthenticated request is rejected."""
        resp = await async_client.post(
            f"/instructor/activity/{COURSE_ID}/1/grade/manual",
            json={
                "student_email": "student@mef.edu.tr",
                "score": 50.0,
            },
        )

        assert resp.status_code == 401


class TestActivityLogs:
    """GET /instructor/activities/{activity_id}/logs endpoint behavior."""

    async def test_activity_logs_returns_events(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Authorized instructor can list score events for an activity."""
        fake_result = {
            "logs": [
                {
                    "id": "log-1",
                    "activityId": "activity-1",
                    "studentName": "b@mef.edu.tr",
                    "studentEmail": "b@mef.edu.tr",
                    "score": 2,
                    "objectiveMetadata": {"completed": True},
                    "timestamp": "2026-05-14T10:00:00+00:00",
                    "eventType": "SUBMISSION",
                }
            ]
        }
        with patch("app.main.listActivityLogs", new_callable=AsyncMock) as mock_logs:
            mock_logs.return_value = fake_result

            resp = await async_client.get("/instructor/activities/activity-1/logs")

        assert resp.status_code == 200
        body = resp.json()
        assert body["logs"][0]["studentName"] == "b@mef.edu.tr"
        assert body["logs"][0]["score"] == 2
