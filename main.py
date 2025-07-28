from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import httpx
import re

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI app with Swagger documentation
app = FastAPI(
    title="Patient Management API",
    description="API for managing patients in HIS system",
    version="1.0.0"
)

# Models
class PatientCreate(BaseModel):
    lastname: str
    firstname: str
    midname: str
    bdate: str  # Format: "1990-01-15"
    cllogin: str
    # clpassword is dropped as per requirements

class Token(BaseModel):
    access_token: str
    token_type: str

class PatientUpdateResponse(BaseModel):
    success: bool

# Constants for HIS API
HIS_CONSTANTS = {
    "pT": "89999999999",
    "ru3": "Другое",
    "apikey": "hadassa",
    "qqc235": "aoAA",
    "qqc153": "оABAAAa",
    "qqc244": "оAAdAAEAFAA",
    "unauthorized": "1"
}

HIS_ENDPOINT = "http://192.168.156.43/cgi-bin/rest/findPatient"

# Authentication
CREDENTIALS = {
    "admin": "secret"
}

def authenticate_user(username: str, password: str):
    if username in CREDENTIALS and CREDENTIALS[username] == password:
        return username
    return False

def determine_gender_from_name(firstname: str, midname: str) -> str:
    """Determine gender from Russian name endings"""
    # Check patronymic (middle name) first as it's more reliable
    if midname:
        if midname.endswith(('ич', 'ович', 'евич', 'ьич')):
            return "male"
        elif midname.endswith(('на', 'овна', 'евна', 'ична')):
            return "female"
    
    # Check first name endings
    if firstname:
        firstname_lower = firstname.lower()
        if firstname_lower.endswith(('а', 'я', 'ь')):
            # Most female names end with these
            common_male_exceptions = ['илья', 'никита', 'данила']
            if firstname_lower not in common_male_exceptions:
                return "female"
        else:
            return "male"
    
    return "male"  # default

async def get_current_user(token: str = Depends(oauth2_scheme)):
    # Simple token validation (in production, use proper JWT)
    if token != "valid_token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "admin"

# Endpoints
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": "valid_token", "token_type": "bearer"}

@app.post("/createPatients")
async def create_patient(
    patient: PatientCreate,
    current_user: str = Depends(get_current_user)
):
    # Determine gender from Russian name
    gender = determine_gender_from_name(patient.firstname, patient.midname)
    
    # Transform to HIS API format
    his_payload = {
        "action": "create",
        "RequiredParameters": {
            "pF": patient.lastname,
            "pG": patient.firstname,
            "pH": patient.midname,
            "pI": patient.bdate,
            "pJ": gender,
            "pT": HIS_CONSTANTS["pT"],
            "email": patient.cllogin,
            "ru3": HIS_CONSTANTS["ru3"]
        },
        "apikey": HIS_CONSTANTS["apikey"],
        "qqc235": HIS_CONSTANTS["qqc235"],
        "qqc153": HIS_CONSTANTS["qqc153"],
        "qqc244": HIS_CONSTANTS["qqc244"],
        "unauthorized": HIS_CONSTANTS["unauthorized"]
    }
    
    # Make HTTP request to HIS system
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(HIS_ENDPOINT, json=his_payload)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Error connecting to HIS system: {str(e)}"
            )
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"HIS system error: {e.response.text}"
            )

@app.put("/updatePatients/{pcode}/credentials", response_model=PatientUpdateResponse)
async def update_patient_credentials(
    pcode: str,
    current_user: str = Depends(get_current_user)
):
    # Currently empty implementation as requested
    return PatientUpdateResponse(success=True)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)