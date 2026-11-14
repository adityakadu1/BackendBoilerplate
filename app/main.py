from fastapi import FastAPI
from app.database import engine, Base
#------------------------------------------------------------------------------------
from app.routers.auth import router as auth_router

#------------------------------------------------------------------------------



app = FastAPI(title="My FastAPI Backend")


@app.get("/api/health")
def health_check():
    return {"status": "OK"}

#--------------------------------------------------------------------
app.include_router(auth_router, prefix="/auth", tags=["Auth"])