from dotenv import load_dotenv
from fastapi import FastAPI

from .database import models, engine
from .routes import users, auth


load_dotenv()

models.Base.metadata.create_all(bind=engine)

app = FastAPI()


@app.get("/ping")
async def ping():
    return "pong"


app.include_router(users, prefix="/users", tags=["users"])
app.include_router(auth, prefix="/auth", tags=["auth"])
