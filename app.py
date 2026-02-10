import os
import io
import base64
from flask import Flask, render_template, request, session, redirect, url_for, flash, send_file, jsonify
import qrcode
from dotenv import load_dotenv
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Import the functions we wrote in database.py
from database import log_in, sign_up, save_user_qr, get_user_history, update_qr_title

load_dotenv()

app = Flask(__name__)
# Flask needs this to encrypt the session cookies that remember users
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-secret-for-local-dev")

# --- HELPER FUNCTIONS ---

def generate_qr_base64(url):
    """Generates a QR code and converts it to a base64 string for HTML display."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save image to a bytes buffer in memory
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    # Convert bytes to base64 string
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return img_str

def fetch_page_title(url):
    """Fetches the page title from a URL"""
    try:
        # Add timeout to avoid hanging
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.find('title')
        
        if title and title.string:
            return title.string.strip()
        
        # Fallback: use domain name
        parsed = urlparse(url)
        return parsed.netloc or url
        
    except Exception as e:
        print(f"Error fetching title for {url}: {e}")
        # Fallback: use domain name
        try:
            parsed = urlparse(url)
            return parsed.netloc or url
        except:
            return url

# --- ROUTES ---

@app.route('/')
def index():
    # If a user is logged in, we can show their name or a personalized greeting
    user = session.get('user')
    return render_template('index.html', user=user)

@app.route('/generate', methods=['POST'])
def generate():
    url = request.form.get('url')
    if not url:
        flash("Please enter a URL!")
        return redirect(url_for('index'))

    # Generate the image string
    qr_base64 = generate_qr_base64(url)

    # If the user is logged in, save the URL to their history in Supabase
    if 'user' in session:
        token = session.get('access_token')
        user_id = session['user'].get('id')
        
        # Fetch page title automatically
        title = fetch_page_title(url)
        
        save_user_qr(token, user_id, url, title)  # Pass the token and title

    user = session.get('user')
    return render_template('index.html', qr_code=qr_base64, original_url=url, user=user)

@app.route('/signup', methods=['GET', 'POST'])
def signup_route():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            sign_up(email, password)
            flash("Signup successful! Please log in.")
            return redirect(url_for('login_route'))
        except Exception as e:
            flash(f"Error: {str(e)}")
    user = session.get('user')
    return render_template('signup.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login_route():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            res = log_in(email, password)
            # IMPORTANT: session['user'] must be set correctly
            # Supabase returns the user object in res.user
            session['access_token'] = res.session.access_token  # Save the token
            session['user'] = {'id': res.user.id, 'email': res.user.email}
            
            flash("Welcome back!")
            return redirect(url_for('index'))  # This sends you home after login
        except Exception as e:
            print(f"Login Error: {e}")  # This prints the error to your terminal
            flash("Invalid login credentials.")
    user = session.get('user')
    return render_template('login.html', user=user)

@app.route('/qrcode_image')
def qrcode_image():
    """Generates a QR code image file on demand"""
    url = request.args.get('url')
    if not url:
        return "Error: No URL provided", 400

    # Generate QR Code directly to memory
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to a byte buffer (like a virtual file)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    
    # Send it back to the browser as a real PNG image
    return send_file(buf, mimetype='image/png')

@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login_route'))
    
    token = session.get('access_token')
    user_id = session['user']['id']
    
    # Get sorting parameter from query string
    sort_by = request.args.get('sort', 'date_desc')  # Default: newest first
    
    # Just fetch the data - NO looping or generation here!
    saved_data = get_user_history(token, user_id)
    
    # Apply sorting
    if saved_data:
        if sort_by == 'date_asc':
            saved_data = sorted(saved_data, key=lambda x: x.get('created_at', ''))
        elif sort_by == 'date_desc':
            saved_data = sorted(saved_data, key=lambda x: x.get('created_at', ''), reverse=True)
        elif sort_by == 'title_asc':
            saved_data = sorted(saved_data, key=lambda x: (x.get('title') or x.get('url', '')).lower())
        elif sort_by == 'title_desc':
            saved_data = sorted(saved_data, key=lambda x: (x.get('title') or x.get('url', '')).lower(), reverse=True)
    
    return render_template('dashboard.html', history=saved_data, user=session.get('user'), current_sort=sort_by)

@app.route('/update_title', methods=['POST'])
def update_title():
    """Updates the title of a saved QR code"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    qr_id = data.get('id')
    new_title = data.get('title')
    
    print(f"DEBUG: Received update request - ID: {qr_id}, Title: {new_title}")
    
    if not qr_id or new_title is None:  # Allow empty string
        return jsonify({'error': 'Missing id or title'}), 400
    
    token = session.get('access_token')
    
    try:
        result = update_qr_title(token, qr_id, new_title)
        print(f"DEBUG: Database update result: {result}")
        return jsonify({'success': True, 'title': new_title})
    except Exception as e:
        print(f"Error updating title: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)