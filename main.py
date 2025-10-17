# main.py
import os
import requests
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt  # PyJWT

# ---------- CONFIG (préférer les vars d'environnement en prod) ----------
CAS_BASE = os.getenv("CAS_BASE", "https://cas.ent.auvergnerhonealpes.fr")
# URL publique de ton backend callback : ex: https://studiix-backend.onrender.com/auth/callback
SERVICE_URL = os.getenv("SERVICE_URL", "https://studiix-backend.onrender.com/auth/callback")
# URL frontend (où on redirige ensuite) : ex: https://studiix-frontend.example.com
FRONTEND_BASE = os.getenv("FRONTEND_BASE", "https://vitejsviteljgeg4yb-0gav--5173--96435430.local-credentialless.webcontainer.io")
JWT_SECRET = os.getenv("JWT_SECRET", "change_this_secret_in_prod")
JWT_ALG = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
# ------------------------------------------------------------------------

app = FastAPI(title="Studiix - CAS / EduConnect (ARA)")

# CORS : restreindre en production à ton frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Studiix backend (CAS multi-school) online ✅"}

@app.get("/login")
def login_redirect(school: str = None):
    """
    Redirige vers le CAS central de la région.
    Paramètre `school` attendu : ex 'martiniere-monplaisir' (sans .ent...)
    """
    if not school:
        return JSONResponse({"error": "Paramètre 'school' requis"}, status_code=400)

    # Construire le service (callback) avec le param school, et l'encoder pour CAS
    # Ex: SERVICE_URL?school=martiniere-monplaisir
    service_with_school = f"{SERVICE_URL}?school={quote_plus(school)}"
    encoded_service = quote_plus(service_with_school)

    # URL login CAS (on passe service encodé)
    cas_login = f"{CAS_BASE}/login?service={encoded_service}"

    return RedirectResponse(cas_login)


def generate_jwt(payload: dict):
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload_copy = payload.copy()
    payload_copy.update({"exp": expire})
    token = jwt.encode(payload_copy, JWT_SECRET, algorithm=JWT_ALG)
    # PyJWT returns bytes on some versions; ensure string
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


@app.get("/auth/callback")
def auth_callback(ticket: str = None, school: str = None):
    """
    CAS renvoie ici : /auth/callback?ticket=ST-...&school=xxx
    On valide le ticket via serviceValidate et on génère un JWT.
    """
    if not ticket or not school:
        return JSONResponse({"error": "Paramètres 'ticket' et 'school' requis"}, status_code=400)

    # Recomposer service param (doit correspondre exactement à celle envoyée au CAS)
    service_with_school = f"{SERVICE_URL}?school={quote_plus(school)}"
    validate_url = f"{CAS_BASE}/serviceValidate?ticket={quote_plus(ticket)}&service={quote_plus(service_with_school)}"

    try:
        resp = requests.get(validate_url, timeout=10)
    except Exception as e:
        return JSONResponse({"error": f"Erreur réseau vers CAS : {str(e)}"}, status_code=502)

    if resp.status_code != 200:
        return JSONResponse({"error": "Erreur lors de la validation CAS"}, status_code=502)

    # Parser la réponse XML CAS
    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError:
        return JSONResponse({"error": "Réponse CAS non XML / parse error"}, status_code=502)

    # Détection namespace si présent
    ns = {}
    if "}" in root.tag:
        ns_uri = root.tag.split("}")[0].strip("{")
        ns = {"cas": ns_uri}

    # Chercher authenticationSuccess
    auth_success = root.find("cas:authenticationSuccess", ns) if ns else root.find(".//authenticationSuccess")
    if auth_success is None:
        return JSONResponse({"error": "Ticket invalide ou utilisateur non authentifié"}, status_code=401)

    # récupérer identifiant user (cas:user)
    user_elem = auth_success.find("cas:user", ns) if ns else auth_success.find("user")
    user_id = user_elem.text if user_elem is not None else None

    # extraire attributs éventuels
    attributes = {}
    if ns:
        attrs_node = auth_success.find("cas:attributes", ns)
        if attrs_node is not None:
            for child in list(attrs_node):
                tag = child.tag.split("}")[1] if "}" in child.tag else child.tag
                attributes[tag] = child.text
    else:
        # fallback : lire children after user
        for child in list(auth_success):
            if child.tag not in ("user",):
                attributes[child.tag] = child.text

    # --- Ici tu peux appeler l'ENT/Pronote pour récupérer matières/notes ---
    try:
        subjects = fetch_subjects_for_user_via_ent(school, user_id, ticket)
    except Exception as e:
        # On ne casse pas le flux pour des erreurs non critiques, on renvoie la simulation
        subjects = simulate_fetch_subjects_for_user(user_id)

    # Générer JWT court
    payload = {"sub": user_id, "user": {"id": user_id, "attributes": attributes}, "subjects": subjects}
    token = generate_jwt(payload)

    # Rediriger vers le frontend en passant le token (pour test). En prod → cookie HttpOnly
    redirect_to = f"{FRONTEND_BASE}/?token={quote_plus(token)}"
    return RedirectResponse(redirect_to)


def simulate_fetch_subjects_for_user(user_id: str):
    if not user_id:
        return []
    # Simulation simple
    return ["Français", "Mathématiques", "Histoire-Géographie", "Anglais"]


def fetch_subjects_for_user_via_ent(school: str, user_id: str, cas_ticket: str):
    """
    POINT D'INSERT RÉEL pour appeler l'ENT / Pronote :
    - Méthode 1 : Si ton ENT expose une API REST, appelle-la en fournissant le ticket.
    - Méthode 2 : Si Pronote est accessible via ENT et pronotepy supporte CAS/session, initialise pronotepy ici.

    Exemples / PSEUDO :
    ent_base = f"https://{school}.ent.auvergnerhonealpes.fr"
    api_url = ent_base + "/api/user/subjects"  # hypothétique
    resp = requests.get(api_url, headers={"Authorization": f"Bearer {some_token_or_ticket}"})
    return resp.json()

    Ici on renvoie une simulation par défaut.
    """
    # TODO : remplacer par logique réelle selon ce que l'établissement fournit.
    # Exemple commenté pour pronotepy (attention : dépend de la config Pronote/ENT)
    #
    # import pronotepy
    # ent_pronote_url = f"https://{school}.ent.auvergnerhonealpes.fr/pronote/eleve.html"
    # client = pronotepy.Client(url=ent_pronote_url, ticket=cas_ticket)  # si pronotepy supporte 'ticket'
    # if client.logged_in:
    #     return [s.name for s in client.current_period.subjects]
    #
    # Sinon appeler une API interne fournie par l'ENT.
    #
    raise Exception("fetch_subjects_for_user_via_ent non implémentée — adapter selon ENT/Pronote de l'établissement")


# Endpoint pour vérifier token depuis frontend
class VerifyRequest(BaseModel):
    token: str

@app.post("/verify-token")
def verify_token(data: VerifyRequest):
    try:
        payload = jwt.decode(data.token, JWT_SECRET, algorithms=[JWT_ALG])
        return {"ok": True, "payload": payload}
    except jwt.ExpiredSignatureError:
        return JSONResponse({"error": "Token expiré"}, status_code=401)
    except Exception as e:
        return JSONResponse({"error": "Token invalide: " + str(e)}, status_code=401)
