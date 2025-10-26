# --- 1. Imports ---
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

app.config['SECRET_KEY'] = 'a-very-secret-key-that-you-will-change'
# NEW: Set a generous-but-safe 100MB upload limit
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 

# Configure the database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure the folder where uploads will be stored
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

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
    saved_filename = db.Column(db.String(255), nullable=False, unique=True)
    upload_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"File('{self.original_filename}', '{self.client_name}')"

# --- 4. Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 5. Public Routes (File Upload) ---

# UPDATED: This function is now new
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """
    The main page with the file upload form.
    NOW HANDLES MULTIPLE FILES.
    """
    if request.method == 'POST':
        client_name = request.form['name']
        client_email = request.form['email']
        
        # NEW: Get a LIST of files
        files = request.files.getlist('file')

        if not files or files[0].filename == '':
            flash('No files selected.', 'error')
            return redirect(request.url)
        
        # NEW: Loop through each file in the list
        for file in files:
            if file: 
                # NEW: Use microseconds (%f) to make timestamp unique for each file
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f") 
                secure_name = f"{timestamp}_{file.filename}"
                
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_name)
                file.save(file_path)

                # NEW: Create a new FileUpload record for *each* file
                new_upload = FileUpload(
                    client_name=client_name,
                    client_email=client_email,
                    original_filename=file.filename,
                    saved_filename=secure_name
                )
                db.session.add(new_upload)

        # NEW: Commit all new records to the database AT ONCE
        db.session.commit()
        
        # NEW: Flash a new message showing how many files were uploaded
        flash(f'Success! {len(files)} file(s) have been securely uploaded.', 'success')
        return redirect(url_for('upload_file'))

    return render_template('upload.html')

# --- 6. Admin Routes (Login, Dashboard, etc.) ---
# (These routes are all correct and do not need changes)

@app.route('/admin/register', methods=['GET', 'POST'])
def register():
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
    all_files = FileUpload.query.order_by(FileUpload.upload_timestamp.desc()).all()
    return render_template('dashboard.html', files=all_files)

@app.route('/admin/download/<string:filename>')
@login_required 
def download_file(filename):
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        filename, 
        as_attachment=True
    )

@app.route('/admin/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# --- 7. Run the App ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)