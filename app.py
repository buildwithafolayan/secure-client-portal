# --- 1. Imports ---
# Import Flask and our new tools
from flask import (Flask, render_template, request, redirect, url_for, 
                   flash, send_from_directory)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, 
                         logout_user, login_required, current_user)
from flask_bcrypt import Bcrypt
import os
from datetime import datetime

# --- 2. App Initialization & Configuration ---
app = Flask(__name__)

# Set a secret key for session management (used by Flask-Login)
# In production, this should be a long, random string
app.config['SECRET_KEY'] = 'my_super_secret_key_change_this_later'

# Configure the database
# This sets up a simple 'sqlite' database file named 'database.db'
# in our project folder.
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure the folder where uploads will be stored
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')

# Create the 'uploads' folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize our tools
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# Tell Flask-Login what page to redirect to if a user tries
# to access a protected page without being logged in.
login_manager.login_view = 'login'
login_manager.login_message_category = 'info' # Optional: for styling flash messages

# --- 3. Database Models ---
# We define our database "tables" as Python classes
# UserMixin is a helper class from Flask-Login

class User(db.Model, UserMixin):
    """
    Our User model for the admin.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Passwords will be 60 chars long after hashing
    password_hash = db.Column(db.String(60), nullable=False)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Checks if a provided password matches the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)

class FileUpload(db.Model):
    """
    Our FileUpload model to track uploaded files.
    """
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(100), nullable=False)
    client_email = db.Column(db.String(100), nullable=False)
    # The original filename
    original_filename = db.Column(db.String(255), nullable=False)
    # The secure, saved filename (to prevent conflicts)
    saved_filename = db.Column(db.String(255), nullable=False, unique=True)
    upload_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"File('{self.original_filename}', '{self.client_name}')"

# --- 4. Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    """
    Flask-Login uses this function to reload the user object
    from the user ID stored in the session.
    """
    return User.query.get(int(user_id))

# --- 5. Public Routes (File Upload) ---

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """
    The main page with the file upload form.
    """
    if request.method == 'POST':
        # Get form data
        client_name = request.form['name']
        client_email = request.form['email']
        
        # Check if the 'file' part is in the request
        if 'file' not in request.files:
            flash('No file part in the request.', 'error')
            return redirect(request.url)
        
        file = request.files['file']

        # If the user does not select a file
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)

        if file:
            # Create a secure, unique filename
            # We use a timestamp + original name to make it unique
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            secure_name = f"{timestamp}_{file.filename}"
            
            # Save the file to our 'uploads' folder
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_name)
            file.save(file_path)

            # Create a new FileUpload record in the database
            new_upload = FileUpload(
                client_name=client_name,
                client_email=client_email,
                original_filename=file.filename,
                saved_filename=secure_name
            )
            db.session.add(new_upload)
            db.session.commit()

            flash('Your file has been securely uploaded. We will be in touch!', 'success')
            return redirect(url_for('upload_file'))

    return render_template('upload.html')

# --- 6. Admin Routes (Login, Dashboard, etc.) ---

@app.route('/admin/register', methods=['GET', 'POST'])
def register():
    """
    A page to create the *first* admin user.
    We'll hide this page after we create our account.
    """
    # This check prevents anyone from registering if an admin already exists
    if User.query.first():
         flash('An admin account already exists.', 'info')
         return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Create a new user, set the hashed password
        user = User(username=username)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Admin account created! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    """
    The admin login page.
    """
    # If user is already logged in, send them to the dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Find the user in the database by their username
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists AND if the password is correct
        if user and user.check_password(password):
            login_user(user) # This is the Flask-Login magic
            flash('Login successful!', 'success')
            # Redirect to the page they were trying to access, or dashboard
            return redirect(request.args.get('next') or url_for('dashboard'))
        else:
            flash('Login failed. Check username and password.', 'error')
            
    return render_template('login.html')

@app.route('/admin/dashboard')
@login_required  # This is the "lock" that protects the page
def dashboard():
    """
    The protected admin dashboard.
    """
    # Query the database to get all file uploads, most recent first
    all_files = FileUpload.query.order_by(FileUpload.upload_timestamp.desc()).all()
    
    return render_template('dashboard.html', files=all_files)

@app.route('/admin/download/<string:filename>')
@login_required # Also protect the download route
def download_file(filename):
    """
    A secure route to download a file.
    """
    # 'send_from_directory' securely provides the file
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        filename, 
        as_attachment=True # This tells the browser to download it
    )

@app.route('/admin/logout')
def logout():
    """
    Logs the user out.
    """
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# --- 7. Run the App ---
if __name__ == '__main__':
    # This block is new.
    # It creates the database tables *before* the app runs
    # for the first time.
    with app.app_context():
        db.create_all()
    app.run(debug=True)