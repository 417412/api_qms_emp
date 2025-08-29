from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, validator
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

# Email validation regex pattern
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Models
class PatientCreate(BaseModel):
    lastname: str
    firstname: str
    midname: str
    bdate: str  # Format: "YYYY-MM-DD"
    cllogin: str  # Must be a valid email
    clpassword: str
    
    @validator('bdate')
    def validate_bdate(cls, v):
        """Validate birthdate format YYYY-MM-DD"""
        try:
            # Try to parse the date to ensure it's valid
            datetime.strptime(v, '%Y-%m-%d')
            return v
        except ValueError:
            raise ValueError('bdate must be in YYYY-MM-DD format (e.g., "1990-01-15")')
    
    @validator('cllogin')
    def validate_email(cls, v):
        """Validate that cllogin is a valid email address"""
        if not EMAIL_REGEX.match(v):
            raise ValueError('cllogin must be a valid email address (e.g., "user@example.com")')
        return v

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

HIS_ENDPOINT = "http://192.168.156.118/cgi-bin/rest/findPatient"
PCODE_ENDPOINT = "http://192.168.156.118/cgi-bin/pBforqqc"

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

def convert_date_format(date_str: str) -> str:
    """Convert date from YYYY-MM-DD to DD.MM.YYYY format"""
    try:
        # Parse the input date
        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
        # Return in DD.MM.YYYY format
        return date_obj.strftime('%d.%m.%Y')
    except ValueError as e:
        raise ValueError(f"Invalid date format: {date_str}. Expected YYYY-MM-DD")

async def get_pcode_from_qqc153(qqc153: str) -> str:
    """Get pcode from HIS using qqc153"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{PCODE_ENDPOINT}?arg={qqc153}")
            response.raise_for_status()
            # Return the plaintext response, stripped of whitespace
            return response.text.strip()
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Error connecting to pBforqqc service: {str(e)}"
            )
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"pBforqqc service error: {e.response.text}"
            )

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

@app.post("/createPatients", status_code=status.HTTP_201_CREATED)
async def create_patient(
    patient: PatientCreate,
    current_user: str = Depends(get_current_user)
):
    # Determine gender from Russian name
    gender = determine_gender_from_name(patient.firstname, patient.midname)
    
    # Convert birthdate from YYYY-MM-DD to DD.MM.YYYY
    try:
        formatted_bdate = convert_date_format(patient.bdate)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    # Transform to HIS API format
    his_payload = {
        "action": "create",
        "RequiredParameters": {
            "pF": patient.lastname,
            "pG": patient.firstname,
            "pH": patient.midname,
            "pI": formatted_bdate,  # Now in DD.MM.YYYY format
            "pJ": gender,
            "pT": HIS_CONSTANTS["pT"],
            "email": patient.cllogin,  # Already validated as email
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
            his_response = response.json()
            
            # Check if response is successful and contains qqc153
            if his_response.get("success") and "data" in his_response and "qqc153" in his_response["data"]:
                # Get the special pcode using qqc153
                qqc153_value = his_response["data"]["qqc153"]
                pcode = await get_pcode_from_qqc153(qqc153_value)
                
                # Replace qqc153 with pcode in the response
                his_response["data"]["pcode"] = pcode
                del his_response["data"]["qqc153"]
            
            return his_response
            
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
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=10443,
        ssl_keyfile="/path/to/your/private.key",
        ssl_certfile="/path/to/your/certificate.crt",
        ssl_ca_certs="/path/to/your/chain.crt"  # Optional: if you have a certificate chain
    )