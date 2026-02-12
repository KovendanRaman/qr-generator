import os
import io
import base64
from flask import Flask, render_template, request, session, redirect, url_for, flash, send_file, jsonify
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import (
    SquareModuleDrawer, GappedSquareModuleDrawer, CircleModuleDrawer,
    RoundedModuleDrawer, VerticalBarsDrawer, HorizontalBarsDrawer
)
from PIL import Image, ImageDraw, ImageFont
from dotenv import load_dotenv
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Import the functions we wrote in database.py
from database import log_in, sign_up, save_user_qr, get_user_history, update_qr_title
from postgrest.exceptions import APIError
from supabase import AuthApiError, AuthInvalidCredentialsError

load_dotenv()

app = Flask(__name__)
# Flask needs this to encrypt the session cookies that remember users
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-secret-for-local-dev")

# --- HELPER FUNCTIONS ---

# QR Code Style Presets
STYLE_PRESETS = {
    'square': SquareModuleDrawer(),
    'rounded': RoundedModuleDrawer(),
    'circle': CircleModuleDrawer(),
    'gapped': GappedSquareModuleDrawer(),
    'vertical': VerticalBarsDrawer(),
    'horizontal': HorizontalBarsDrawer(),
}

def generate_qr_base64(url, center_text=None, style="square"):
    """Generates a QR code with custom style pattern and optional center text."""
    # Use high error correction so center text doesn't break scanning
    qr = qrcode.QRCode(
        version=1, 
        box_size=10, 
        border=5,
        error_correction=qrcode.constants.ERROR_CORRECT_H
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    # Use styled image with selected pattern
    module_drawer = STYLE_PRESETS.get(style, SquareModuleDrawer())
    img = qr.make_image(
        image_factory=StyledPilImage,
        module_drawer=module_drawer,
        fill_color="black",
        back_color="white"
    )
    
    # Add center text if provided
    if center_text and center_text.strip():
        img = img.convert('RGB')
        draw = ImageDraw.Draw(img)
        
        # Calculate center position and text size
        img_width, img_height = img.size
        
        # Try to use a nice font, fall back to default if unavailable
        try:
            font_size = max(20, img_width // 15)
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            font = ImageFont.load_default()
        
        # Get text bounding box
        bbox = draw.textbbox((0, 0), center_text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        # Always use high contrast colors for center text readability
        # White background with black text for maximum readability
        text_bg_color = "white"
        text_color = "black"
        
        # Draw background rectangle for text
        padding = 10
        rect_x1 = (img_width - text_width) // 2 - padding
        rect_y1 = (img_height - text_height) // 2 - padding
        rect_x2 = (img_width + text_width) // 2 + padding
        rect_y2 = (img_height + text_height) // 2 + padding
        
        draw.rectangle([rect_x1, rect_y1, rect_x2, rect_y2], fill=text_bg_color)
        
        # Draw the text in black for best readability
        text_x = (img_width - text_width) // 2
        text_y = (img_height - text_height) // 2
        draw.text((text_x, text_y), center_text, fill=text_color, font=font)
    
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

    # Get design parameters from form (with defaults)
    center_text = request.form.get('center_text', '').strip()
    style = request.form.get('style', 'square') or 'square'

    # Generate the image string with custom design
    qr_base64 = generate_qr_base64(url, center_text, style)

    # If the user is logged in, save the URL and design to their history in Supabase
    if 'user' in session:
        token = session.get('access_token')
        user_id = session['user'].get('id')
        
        # Fetch page title automatically
        title = fetch_page_title(url)
        
        # Save with design parameters
        save_user_qr(token, user_id, url, title, center_text, style)

    user = session.get('user')
    return render_template('index.html', qr_code=qr_base64, original_url=url, user=user, 
                          center_text=center_text, style=style)

@app.route('/signup', methods=['GET', 'POST'])
def signup_route():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            res = sign_up(email, password)
            # When "Confirm email" is disabled, Supabase returns session; log user in and go to app
            if getattr(res, 'session', None) and res.session:
                session['access_token'] = res.session.access_token
                session['user'] = {'id': res.user.id, 'email': res.user.email}
                flash("Account created! Welcome.")
                return redirect(url_for('index'))
            # Email confirmation required
            flash("Account created! Please check your email to confirm, then log in.")
            return redirect(url_for('login_route'))
        except AuthApiError as e:
            msg = str(e).lower()
            if "already registered" in msg or "already exists" in msg:
                flash("This email is already registered. Try logging in or use a different email.", "error")
            else:
                flash(f"Sign up failed: {str(e)}", "error")
        except Exception as e:
            flash(f"Sign up failed: {str(e)}", "error")
    user = session.get('user')
    return render_template('signup.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login_route():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            res = log_in(email, password)
            session['access_token'] = res.session.access_token
            session['user'] = {'id': res.user.id, 'email': res.user.email}
            flash("Welcome back!")
            return redirect(url_for('index'))
        except AuthInvalidCredentialsError:
            flash("Invalid email or password. If you don't have an account, sign up first.", "error")
        except AuthApiError as e:
            msg = str(e).lower()
            if "invalid" in msg and ("credential" in msg or "password" in msg or "login" in msg):
                flash("Invalid email or password. If you don't have an account, sign up first.", "error")
            else:
                flash(f"Login failed: {str(e)}", "error")
        except Exception as e:
            print(f"Login Error: {e}")
            flash("Invalid email or password. If you don't have an account, sign up first.", "error")
    user = session.get('user')
    return render_template('login.html', user=user)

@app.route('/qrcode_image')
def qrcode_image():
    """Generates a QR code image file on demand with custom design options"""
    url = request.args.get('url')
    if not url:
        return "Error: No URL provided", 400

    # Get design parameters from query string (with defaults)
    center_text = request.args.get('center_text', '').strip()
    style = request.args.get('style', 'square') or 'square'

    # Use high error correction for center text
    qr = qrcode.QRCode(
        version=1, 
        box_size=10, 
        border=5,
        error_correction=qrcode.constants.ERROR_CORRECT_H
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    # Use styled image with selected pattern
    module_drawer = STYLE_PRESETS.get(style, SquareModuleDrawer())
    img = qr.make_image(
        image_factory=StyledPilImage,
        module_drawer=module_drawer,
        fill_color="black",
        back_color="white"
    )
    
    # Add center text if provided
    if center_text:
        img = img.convert('RGB')
        draw = ImageDraw.Draw(img)
        
        img_width, img_height = img.size
        
        try:
            font_size = max(20, img_width // 15)
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            font = ImageFont.load_default()
        
        bbox = draw.textbbox((0, 0), center_text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        # Always use high contrast colors for center text readability
        # White background with black text for maximum readability
        text_bg_color = "white"
        text_color = "black"
        
        padding = 10
        rect_x1 = (img_width - text_width) // 2 - padding
        rect_y1 = (img_height - text_height) // 2 - padding
        rect_x2 = (img_width + text_width) // 2 + padding
        rect_y2 = (img_height + text_height) // 2 + padding
        
        draw.rectangle([rect_x1, rect_y1, rect_x2, rect_y2], fill=text_bg_color)
        
        text_x = (img_width - text_width) // 2
        text_y = (img_height - text_height) // 2
        draw.text((text_x, text_y), center_text, fill=text_color, font=font)
    
    # Save to a byte buffer
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png')

def _title_sort_key(x):
    """Safe sort key for title; handle None/missing or non-strings."""
    raw = x.get("title") or x.get("url") or ""
    return str(raw).lower()


def _fetch_sorted_history(token, user_id, sort_by):
    """Fetch user history from DB and apply sort. Returns (list, error_msg). error_msg is None on success."""
    saved_data = []
    try:
        saved_data = get_user_history(token, user_id)
    except APIError as e:
        err_str = str(e).lower()
        if "jwt expired" in err_str or "pgrst303" in err_str:
            return None, "session_expired"
        if "502" in err_str or "bad gateway" in err_str or "503" in err_str:
            try:
                saved_data = get_user_history(token, user_id)
            except Exception:
                pass
        if not saved_data:
            return [], "api_error"
    except Exception:
        return [], "api_error"
    saved_data = saved_data or []
    if saved_data:
        if sort_by == 'date_asc':
            saved_data = sorted(saved_data, key=lambda x: x.get('created_at', ''))
        elif sort_by == 'date_desc':
            saved_data = sorted(saved_data, key=lambda x: x.get('created_at', ''), reverse=True)
        elif sort_by == 'title_asc':
            saved_data = sorted(saved_data, key=_title_sort_key)
        elif sort_by == 'title_desc':
            saved_data = sorted(saved_data, key=_title_sort_key, reverse=True)
    return saved_data, None


@app.route('/api/history')
def api_history():
    """Returns history as JSON for lazy loading. Requires auth."""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    token = session.get('access_token')
    user_id = session['user']['id']
    sort_by = request.args.get('sort', 'date_desc')
    saved_data, err = _fetch_sorted_history(token, user_id, sort_by)
    if err == "session_expired":
        return jsonify({'error': 'session_expired'}), 401
    if err == "api_error":
        return jsonify({'error': 'Could not load history.', 'history': []}), 200
    return jsonify({'history': saved_data, 'current_sort': sort_by})


@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login_route'))
    sort_by = request.args.get('sort', 'date_desc')
    # Render shell immediately; history is loaded lazily via /api/history in the browser
    return render_template('dashboard.html', history=[], user=session.get('user'), current_sort=sort_by)

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