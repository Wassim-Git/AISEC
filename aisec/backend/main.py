from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import url_scanner, email_scanner, chat_scanner

app = FastAPI(
    title="AISec – AI Security Assistant API",
    description="Protect remote workers from phishing, social engineering, and malicious links.",
    version="1.0.0",
    docs_url="/api-docs",
    redoc_url="/api-redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(url_scanner.router, prefix="/scan", tags=["URL Scanner"])
app.include_router(email_scanner.router, prefix="/scan", tags=["Email Inspector"])
app.include_router(chat_scanner.router, prefix="/scan", tags=["ChatCheck"])

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "AISec API"}

@app.get("/")
def root():
    return {"service": "AISec", "version": "1.0.0", "docs": "/api-docs"}
