from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import pronotepy

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginData(BaseModel):
    url: str
    username: str
    password: str

@app.get("/")
def root():
    return {"message": "Studiix backend online ✅"}

@app.post("/login")
def login(data: LoginData):
    try:
        client = pronotepy.Client(
            url=data.url,
            username=data.username,
            password=data.password,
        )

        if not client.logged_in:
            raise HTTPException(status_code=401, detail="Identifiants incorrects")

        subjects = [s.name for s in client.current_period.subjects]
        return {"message": "Connexion réussie", "subjects": subjects}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
