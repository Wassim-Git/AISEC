from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from utils.chat_analyzer import analyze_chat

router = APIRouter()


class ChatRequest(BaseModel):
    message: str
    platform: str = "unknown"

    class Config:
        json_schema_extra = {
            "example": {
                "message": "HR: All employees must update payroll info immediately at http://hr-update.xyz/payroll",
                "platform": "slack",
            }
        }


@router.post("/chat", summary="Analyze a Slack/Teams message for social engineering")
async def scan_chat(request: ChatRequest):
    """
    Detect social engineering, impersonation, and malicious links in chat messages.

    Identifies:
    - Role impersonation (CEO, HR, IT Support)
    - Urgency manipulation tactics
    - Requests for sensitive actions (gift cards, wire transfer, credentials)
    - Embedded malicious URLs
    """
    if not request.message or len(request.message) < 5:
        raise HTTPException(status_code=400, detail="Message too short to analyze")

    result = analyze_chat(request.message, request.platform)
    return result
