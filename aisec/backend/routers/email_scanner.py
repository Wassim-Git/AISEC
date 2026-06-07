from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from utils.email_analyzer import analyze_email

router = APIRouter()


class EmailRequest(BaseModel):
    eml_text: str

    class Config:
        json_schema_extra = {
            "example": {
                "eml_text": "From: it-support@micros0ft.com\nSubject: URGENT: Your account will be suspended\n\nDear user, click here immediately: http://fake-login.tk"
            }
        }


@router.post("/email", summary="Inspect an email for phishing indicators")
async def scan_email(request: EmailRequest):
    """
    Parse and analyze an email for phishing signals including:
    - SPF/DKIM/DMARC header analysis
    - Urgency and authority language detection
    - Embedded URL extraction and recursive scanning
    - Social engineering pattern recognition
    """
    if not request.eml_text or len(request.eml_text) < 10:
        raise HTTPException(status_code=400, detail="Email content too short")

    result = analyze_email(request.eml_text)
    return result


@router.post("/email/upload", summary="Upload an .eml file for analysis")
async def scan_email_file(file: UploadFile = File(...)):
    """Upload a raw .eml file for phishing analysis."""
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    content = await file.read()
    eml_text = content.decode("utf-8", errors="ignore")
    result = analyze_email(eml_text)
    return result
