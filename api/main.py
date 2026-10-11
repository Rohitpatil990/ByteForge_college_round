"""AgentBreak FastAPI Application.

Entry point for the AgentBreak backend API.
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router

app = FastAPI(
    title="AgentBreak Security Testing API",
    description="Minimal shared API foundation for the AgentBreak AI-agent security testing platform.",
    version="0.1.0",
)

cors_env = os.getenv("CORS_ORIGINS", "")
if cors_env:
    allowed_origins = [orig.strip() for orig in cors_env.split(",") if orig.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

# Enable CORS for dashboard, frontend, and browser extension integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.vercel\.app|chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/", summary="Root index")
def root_index():
    return {
        "app": "AgentBreak Security Testing API",
        "version": "0.1.0",
        "docs_url": "/docs",
        "health_check": "/health",
        "target_configs": "/target/configs",
        "status": "foundation_ready",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)
