import os
import io
import base64
from flask import Flask, render_template, request, session, redirect, url_for, flash
import qrcode
from dotenv import load_dotenv

# Import the functions we wrote in database.py
from database import log_in, sign_up, save_user_qr, get_user_history

load_dotenv()

app = Flask(__name__)
# Flask needs this to encrypt the session cookies that remember users
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-secret-for-local-dev")

# --- HELPER FUNCTION ---

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
        save_user_qr(token, user_id, url)  # Pass the token here

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
    return render_template('signup.html')

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
    return render_template('login.html')

@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login_route'))
    
    token = session.get('access_token')
    user_id = session['user']['id']
    # Fetch list of URLs from Supabase
    saved_data = get_user_history(token, user_id)
    
    # Pass BOTH the history data and the user session data
    return render_template('dashboard.html', history=saved_data, user=session.get('user'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)