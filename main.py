from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pronotepy

app = FastAPI()

# Autorise le frontend à appeler le backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ en prod, mets ton vrai domaine ici
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================
# 🔹 Modèle de requête
# =====================
class EduConnectLogin(BaseModel):
    username: str
    password: str

# =====================
# 🔹 Route test backend
# =====================
@app.get("/")
def home():
    return {"message": "Backend Pronote (EduConnect) opérationnel ✅"}

# =====================
# 🔹 Connexion Pronote
# =====================
@app.post("/pronote/login")
def login_to_pronote(data: EduConnectLogin):
    """
    Connexion à Pronote via EduConnect
    et récupération des matières de l'élève.
    """
    pronote_url = "https://0692866r.index-education.net/pronote/eleve.html"

    try:
        # Connexion via EduConnect
        client = pronotepy.Client(
            url=pronote_url,
            username=data.username,
            password=data.password,
            ent="educonnect",
            ac_ent=True
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur de connexion : {str(e)}")

    if not client.logged_in:
        raise HTTPException(status_code=401, detail="Identifiants invalides ou accès refusé à Pronote.")

    # Récupérer les matières
    try:
        subjects = [s.name for s in client.current_period.subjects]
    except Exception:
        subjects = []

    client.logout()

    return {
        "status": "success",
        "username": data.username,
        "subjects": subjects,
        "message": f"Connexion réussie à Pronote pour {data.username}"
    }
