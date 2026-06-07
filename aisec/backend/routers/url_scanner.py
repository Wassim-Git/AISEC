from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from utils.url_analyzer import analyze_url

router = APIRouter()


class URLRequest(BaseModel):
    url: str

    class Config:
        json_schema_extra = {
            "example": {"url": "https://micros0ft-login.tk/verify"}
        }


class URLResponse(BaseModel):
    score: int
    verdict: str
    timeline: list[str]
    explanation: str
    technical: dict
    features: dict


@router.post("/url", response_model=URLResponse, summary="Scan a URL for phishing indicators")
async def scan_url(request: URLRequest):
    """
    Scan a URL for phishing, malware, and social engineering indicators.

    Returns:
    - **score**: Threat score 0-100 (100 = most dangerous)
    - **verdict**: malicious | suspicious | safe
    - **timeline**: Step-by-step attack narrative
    - **explanation**: Plain-English summary for non-technical users
    - **technical**: Raw feature values for security professionals
    - **features**: ML feature vector used for classification
    """
    if not request.url or len(request.url) < 4:
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    result = analyze_url(request.url)
    return result
