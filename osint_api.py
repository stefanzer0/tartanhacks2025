from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import httpx
import json
import requests

app = FastAPI()

YOUR_NUMLOOKUP_API_KEY = open("../Credentials/numlookup_api.txt").read().strip()

app = FastAPI()

# Enable CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all frontend origins (change this later for security)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods
    allow_headers=["*"],  # Allows all headers
)

# Sample endpoint for testing CORS
@app.get("/")
async def root():
    return {"message": "CORS is now enabled!"}

# Load WhatsMyName JSON data
with open("./WhatsMyName/wmn-data.json", "r", encoding="utf-8") as file:
    services = json.load(file)

# Function to check username availability across social media
async def check_username(username: str):
    results = {}
    for service in services["sites"]:
        url = service["uri_check"].replace("{account}", username)
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == service["e_code"]:
                results[service["name"]] = url  # Found a valid profile
                break
        except requests.exceptions.RequestException:
            continue  # Skip errors
    return results if results else {"status": "No accounts found"}

# Function to check email breaches
async def check_breaches(email: str):
    HIBP_API = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    async with httpx.AsyncClient() as client:
        response = await client.get(HIBP_API)
        return response.json() if response.status_code == 200 else {"breaches": "None found"}

# Function to check IP geolocation
async def lookup_ip(ip: str):
    IP_API = f"http://ip-api.com/json/{ip}"
    async with httpx.AsyncClient() as client:
        response = await client.get(IP_API)
        return response.json() if response.status_code == 200 else {"location": "Unknown"}

async def lookup_phone(phone: str):
    API_URL = f"https://www.numlookupapi.com/api/v1/validate?number={phone}&apikey={YOUR_NUMLOOKUP_API_KEY}"
    async with httpx.AsyncClient() as client:
        response = await client.get(API_URL)
        return response.json() if response.status_code == 200 else {"phone_info": "No data found"}

@app.get("/osint_search")
async def osint_search(email: str = Query(None), ip: str = Query(None), username: str = Query(None), phone: str = Query(None)):
    results = {}
    if email:
        results["breach_data"] = await check_breaches(email)
    if ip:
        results["ip_location"] = await lookup_ip(ip)
    if username:
        results["social_media_accounts"] = await check_username(username)
    if phone:
        results["phone_info"] = await lookup_phone(phone)
    return results

