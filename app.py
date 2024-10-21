from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import calendar
from functools import wraps
import os



app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///scheduler.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    bookings = db.relationship('Booking', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_name = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='approved')  # Add this line
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Add a function to recreate the database
def reset_database():
    with app.app_context():
        # Drop all existing tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        # Create your admin account
        admin = User(username='your_username', is_admin=True)
        admin.set_password('your_secure_password')
        db.session.add(admin)
        db.session.commit()
        print("Database reset and admin user created")

# Uncomment to reset database
# reset_database()
class TimeSlotRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_name = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('calendar_view'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def calendar_view():
    # Get current month and year
    now = datetime.now()
    year = now.year
    month = now.month

    # Create calendar matrix
    cal = calendar.monthcalendar(year, month)
    
    # Fetch bookings for the current month
    bookings = Booking.query.filter(
        Booking.start_time >= datetime(year, month, 1),
        Booking.start_time < datetime(year, month + 1 if month < 12 else 1, 1 if month < 12 else 1)
    ).all()

    return render_template('calendar.html', 
                           calendar=cal, 
                           year=year, 
                           month=month, 
                           month_name=calendar.month_name[month],
                           bookings=bookings)

@app.route('/request_slot', methods=['GET', 'POST'])
@login_required
def request_slot():
    if request.method == 'POST':
        start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M')
        end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
        
        # Create a new time slot request
        new_request = TimeSlotRequest(
            employee_name=current_user.username,
            start_time=start_time,
            end_time=end_time,
            user_id=current_user.id
        )
        
        db.session.add(new_request)
        db.session.commit()
        
        flash('Time slot request submitted')
        return redirect(url_for('calendar_view'))
    
    return render_template('request_slot.html')

# Modify admin routes to check for admin privileges
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('calendar_view'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/requests')
@login_required
@admin_required
def manage_requests():
    # Fetch pending time slot requests
    requests = TimeSlotRequest.query.filter_by(status='pending').all()
    
    return render_template('manage_requests.html', requests=requests)

@app.route('/admin/approve_request/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_request(request_id):
    time_slot_request = TimeSlotRequest.query.get_or_404(request_id)
    
    # Check for overlapping bookings
    overlapping = Booking.query.filter(
        (Booking.start_time < time_slot_request.end_time) & 
        (Booking.end_time > time_slot_request.start_time)
    ).first()
    
    if overlapping:
        flash('This time slot conflicts with an existing booking')
        return redirect(url_for('manage_requests'))
    
    # Create a new booking
    new_booking = Booking(
        employee_name=time_slot_request.employee_name,
        start_time=time_slot_request.start_time,
        end_time=time_slot_request.end_time,
        user_id=time_slot_request.user_id,
        status='approved'
    )
    
    # Update request status
    time_slot_request.status = 'approved'
    
    db.session.add(new_booking)
    db.session.commit()
    
    flash('Time slot request approved')
    return redirect(url_for('manage_requests'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check if any admin account exists
    admin_exists = User.query.filter_by(is_admin=True).first()
    
    if current_user.is_authenticated:
        return redirect(url_for('calendar_view'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Always create non-admin users
        new_user = User(username=username, is_admin=False)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/admin/reject_request/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def reject_request(request_id):
    time_slot_request = TimeSlotRequest.query.get_or_404(request_id)
    time_slot_request.status = 'rejected'
    
    db.session.commit()
    
    flash('Time slot request rejected')
    return redirect(url_for('manage_requests'))

# Initial admin user creation (run once)
def create_admin():
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', is_admin=True)
            admin.set_password('your_admin_password')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created")

if __name__ == '__main__':
    # Uncomment to create admin user
    # create_admin()
    app.run(debug=True)