"""AgentBreak FastAPI Application.

Entry point for the AgentBreak backend API.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router

app = FastAPI(
    title="AgentBreak Security Testing API",
    description="Minimal shared API foundation for the AgentBreak AI-agent security testing platform.",
    version="0.1.0",
)

# Enable CORS for dashboard and frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
