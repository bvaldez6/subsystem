# backend/main_example.py
import uvicorn
from fastapi import FastAPI
from backend.routes.exploitation import router as exploitation_router

app = FastAPI(title="DEM Subsystem 4 (Exploitation)")
app.include_router(exploitation_router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
