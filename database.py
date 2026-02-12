import os
import logging
from dotenv import load_dotenv
from supabase import create_client, Client, ClientOptions

load_dotenv()

logger = logging.getLogger(__name__)

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

# --- USER-SPECIFIC CLIENT ---

def get_user_client(access_token):
    """Function to get a client that 'is' the user"""
    return create_client(
        os.environ.get("SUPABASE_URL"),
        os.environ.get("SUPABASE_KEY"),  # Use the ANON key here for RLS
        options=ClientOptions(
            headers={"Authorization": f"Bearer {access_token}"}
        )
    )

# --- AUTH FUNCTIONS ---

def sign_up(email, password):
    """Registers a new user in Supabase Auth"""
    return supabase.auth.sign_up({"email": email, "password": password})

def log_in(email, password):
    """Logs in an existing user"""
    return supabase.auth.sign_in_with_password({"email": email, "password": password})

# --- DATA FUNCTIONS ---

def save_user_qr(access_token, user_id, url_string, title=None, center_text=None, style='square'):
    """Saves a URL and its design for a specific user using their UUID"""
    logger.debug("Saving QR for user_id=%s style=%s", user_id, style)
    
    # Get user-specific client with their auth token
    user_client = get_user_client(access_token)
    data = {
        "userid": user_id, 
        "url": url_string, 
        "title": title,
        "center_text": center_text if center_text else None,
        "style": style
    }
    # This now passes the auth.uid() check!
    return user_client.table("saved_qrs").insert(data).execute()

def get_user_history(access_token, user_id):
    """Fetches all saved URLs for a specific user"""
    from postgrest.exceptions import APIError
    user_client = get_user_client(access_token)
    # Try 'userid' first, then 'user_id' (Supabase often uses snake_case)
    last_error = None
    for column in ("userid", "user_id"):
        try:
            response = user_client.table("saved_qrs").select("*").eq(column, user_id).execute()
            return response.data or []
        except APIError as e:
            last_error = e
            continue
    if last_error:
        raise last_error
    return []

def update_qr_title(access_token, qr_id, new_title):
    """Updates the title of a saved QR code"""
    logger.debug("Updating QR title for qr_id=%s", qr_id)
    user_client = get_user_client(access_token)
    result = user_client.table("saved_qrs").update({"title": new_title}).eq("id", qr_id).execute()
    logger.debug("QR title update completed for qr_id=%s", qr_id)
    return result