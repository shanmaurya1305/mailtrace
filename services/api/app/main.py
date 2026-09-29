import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.schemas import HealthResponse
from app.api.routes.forensics import router as forensics_router
from app.api.routes.threat import router as threat_router
from app.api.routes.investigation import router as investigation_router

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("mailtrace-api")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="2.0.0",
    description="MAILTRACE 2.0 AI-Powered Email Forensics & Threat Intelligence API Foundation"
)

# Configure CORS dynamically from environment variables, including chrome-extension origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=r"^chrome-extension://[a-zA-Z0-9]+$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API v1 routers
app.include_router(forensics_router, prefix="/api")
app.include_router(threat_router, prefix="/api")
app.include_router(investigation_router, prefix="/api")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception during request processing: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

@app.get("/api/health", response_model=HealthResponse)
async def get_health():
    """Health check endpoint required for API connectivity verification."""
    return HealthResponse(
        status="ok",
        service=settings.SERVICE_NAME
    )
