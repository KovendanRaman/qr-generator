import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

# --- AUTH FUNCTIONS ---

def sign_up(email, password):
    """Registers a new user in Supabase Auth"""
    return supabase.auth.sign_up({"email": email, "password": password})

def log_in(email, password):
    """Logs in an existing user"""
    return supabase.auth.sign_in_with_password({"email": email, "password": password})

# --- DATA FUNCTIONS ---

def save_user_qr(user_id, url_string):
    """Saves a URL for a specific user using their UUID"""
    # Note: Using 'userid' to match your Supabase screenshot
    data = {"userid": user_id, "url": url_string}
    response = supabase.table("saved_qrs").insert(data).execute()
    return response

def get_user_history(user_id):
    """Fetches all saved URLs for a specific user"""
    # Note: Using 'userid' to match your Supabase screenshot
    response = supabase.table("saved_qrs").select("*").eq("userid", user_id).execute()
    return response.data