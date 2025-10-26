# --- 1. Imports ---
from flask import (Flask, render_template, request, redirect, url_for, 
                   flash, send_from_directory)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, 
                         logout_user, login_required, current_user)
from flask_bcrypt import Bcrypt
from vercel_blob import put # Import Vercel Blob's 'put' function
import os
from datetime import datetime

# --- 2. App Initialization & Configuration ---
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-fallback-key-for-local-dev')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 # 100MB upload limit

# --- VERCEL DATABASE FIX ---
# Get the base directory
basedir = os.path.abspath(os.path.dirname(__file__))

# Check if we are running on Vercel (where '/tmp' is writable)
if os.environ.get('VERCEL'):
    # Save the database in Vercel's temporary '/tmp' folder
    db_path = os.path.join('/tmp', 'database.db')
else:
    # Otherwise, save it in our local project folder
    db_path = os.path.join(basedir, 'database.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
# --- END VERCEL DATABASE FIX ---

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Initialize our tools
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- 3. Database Models (The "Blueprints") ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class FileUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(100), nullable=False)
    client_email = db.Column(db.String(100), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    # This will be the path in Vercel Blob
    blob_path = db.Column(db.String(255), nullable=False, unique=True)
    # We now store the permanent URL
    blob_url = db.Column(db.String(512), nullable=False, unique=True)
    upload_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"File('{self.original_filename}', '{self.client_name}')"

# --- 4. Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    # This needs to be inside a 'with app.app_context()' to work reliably on Vercel
    with app.app_context():
        return User.query.get(int(user_id))

# --- 5. Public Routes (File Upload) ---
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        client_name = request.form['name']
        client_email = request.form['email']
        files = request.files.getlist('file')

        if not files or files[0].filename == '':
            flash('No files selected.', 'error')
            return redirect(request.url)
        
        for file in files:
            if file: 
                # Create a secure path for the blob
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
                # We'll save it in a folder structure based on client email
                secure_path = f"{client_email}/{timestamp}_{file.filename}"
                
                # Upload the file to Vercel Blob
                try:
                    blob = put(
                        pathname=secure_path, 
                        body=file.read(), 
                        add_random_suffix=False # We handle uniqueness
                    )
                    
                    # Create the database record
                    new_upload = FileUpload(
                        client_name=client_name,
                        client_email=client_email,
                        original_filename=file.filename,
                        blob_path=secure_path,
                        blob_url=blob['url'] # Save the URL from Blob
                    )
                    db.session.add(new_upload)
                
                except Exception as e:
                    flash(f'An error occurred during upload: {e}', 'error')
                    return redirect(request.url)

        # Commit all new records to the database AT ONCE
        db.session.commit()
        
        flash(f'Success! {len(files)} file(s) have been securely uploaded.', 'success')
        return redirect(url_for('upload_file'))

    return render_template('upload.html')

# --- 6. Admin Routes (Login, Dashboard, etc.) ---
@app.route('/admin/register', methods=['GET', 'POST'])
def register():
    # NEW: Ensure DB exists right before we use it
    with app.app_context():
        db.create_all()
    
    # Now, check for the user
    with app.app_context():
        if User.query.first():
             flash('An admin account already exists.', 'info')
             return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Admin account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user) 
            flash('Login successful!', 'success')
            return redirect(request.args.get('next') or url_for('dashboard'))
        else:
            flash('Login failed. Check username and password.', 'error')
    return render_template('login.html')

@app.route('/admin/dashboard')
@login_required
def dashboard():
    # FIX: Changed all__files (two underscores) to all_files (one underscore)
    all_files = FileUpload.query.order_by(FileUpload.upload_timestamp.desc()).all()
    return render_template('dashboard.html', files=all_files)

@app.route('/admin/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# --- 7. Database Creation (for Vercel) ---
# Create a simple route that we can call to initialize the database
@app.route('/init-db')
def init_db():
    with app.app_context():
        db.create_all()
    return "Database initialized! (This route is no longer required)"

# --- 8. Run the App (for local development) ---
if __name__ == '__main__':
    with app.app_context():
        # This will create our new 'database.db' in the local folder
        db.create_all()
    app.run(debug=True)

