import os
from dotenv import load_dotenv
from supabase import create_client, Client, ClientOptions

load_dotenv()

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

def save_user_qr(access_token, user_id, url_string):
    """Saves a URL for a specific user using their UUID"""
    # This print will show up in your terminal
    print(f"DEBUG: Saving for User UUID: {user_id}")
    
    # Get user-specific client with their auth token
    user_client = get_user_client(access_token)
    data = {"userid": user_id, "url": url_string}
    # This now passes the auth.uid() check!
    return user_client.table("saved_qrs").insert(data).execute()

def get_user_history(access_token, user_id):
    """Fetches all saved URLs for a specific user"""
    # Get user-specific client with their auth token
    user_client = get_user_client(access_token)
    # Note: Using 'userid' to match your Supabase screenshot
    response = user_client.table("saved_qrs").select("*").eq("userid", user_id).execute()
    return response.data