from flask import Flask, request, redirect, url_for, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os


app = Flask(__name__)

# Initialize the LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'HICHAM' 
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESPONSE_FOLDER'] = 'responses'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initialize the database
db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)

            # Redirect based on the user's role
            if user.role == 'user':
                return redirect(url_for('user_home'))
            elif user.role == 'hr':
                return redirect(url_for('hr_home'))
            else:
                # Handle other cases (e.g., show an error message)
                return "Invalid role for user."

        else:
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role=request.form['role']
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=password_hash, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Define models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Password hash for authentication
    role = db.Column(db.Enum('user', 'hr'), nullable=False)
    requests = db.relationship('Request', backref='user', lazy=True)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    demand_file = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Enum('pending', 'responded'), default='pending')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    responses = db.relationship('Response', backref='request', uselist=False, lazy=True)

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    response_file = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# Ensure the upload and response directories exist
for folder in [app.config['UPLOAD_FOLDER'], app.config['RESPONSE_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/user')
@login_required
def user_home():
    requests = Request.query.filter_by(user_id=current_user.id).all()
    return render_template('user_home.html', requests=requests)

@app.route('/download/<int:request_id>')
@login_required  # Ensures only logged-in users can access this route
def download_request(request_id):
    request_record = Request.query.get(request_id)
    if request_record and request_record.status == 'responded':
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], request_record.demand_file)
        return send_from_directory(directory=app.config['UPLOAD_FOLDER'],
                                   path=request_record.demand_file,
                                   as_attachment=False)
    else:
        return "File not found or request not responded.", 404



@app.route('/user/upload', methods=['GET', 'POST'])
@login_required
def upload_request():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_request = Request(user_id=current_user.id, demand_file=filename)
            db.session.add(new_request)
            db.session.commit()
            return redirect(url_for('user_home'))
    return render_template('upload_request.html')

@app.route('/hr')
@login_required
def hr_home():
    if current_user.role != 'hr':
        return redirect(url_for('user_home'))
    requests = Request.query.all()
    responses = Response.query.all()
    requests_with_responses = []
    for request_item in requests:
        demand = request_item.demand_file
        response = None
        for response_item in responses:
            if response_item.request_id == request_item.id:
                response = response_item.response_file
                break
        requests_with_responses.append({'user': request_item.user.username, 'demand': demand, 'response': response})
    return render_template('hr_home.html', requests=requests_with_responses)

@app.route('/hr/respond/<demand>', methods=['GET', 'POST'])
@login_required
def respond_request(demand):
    if current_user.role != 'hr':
        return redirect(url_for('user_home'))
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            response_filename = f'response_{demand}'
            file.save(os.path.join(app.config['RESPONSE_FOLDER'], response_filename))
            request_item = Request.query.filter_by(demand_file=demand).first()
            if request_item:
                new_response = Response(request_id=request_item.id, response_file=response_filename)
                db.session.add(new_response)
                db.session.commit()
                request_item.status = 'responded'
                db.session.commit()
            return redirect(url_for('hr_home'))
    return render_template('respond_request.html', demand=demand)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/responses/<filename>')
def response_file(filename):
    return send_from_directory(app.config['RESPONSE_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
