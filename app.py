#from email.policy import default
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from config import Congig
from email_service import send_booking_confirmation
from flask import request
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config.from_object(Congig)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = "login"




class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    camp_name = db.Column(db.String(50), nullable=True)
    

class Reports(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    Campus = db.Column(db.String(50), nullable=True)
    block = db.Column(db.String(50), nullable=True)
    description = db.Column(db.String(80), nullable=True)
    status = db.Column(db.String(20), default='Reported', nullable=True)

    def __init__(self, user_id, Campus, block , description,  status=None):
        self.user_id = user_id
        self.Campus = Campus
        self.block = block
        self.description = description
        self.status = status

with app.app_context():
    db.create_all()

from flask import request, flash

@app.route('/register', methods=['GET', 'POST'])
def register():
    title = 'Register'
    campus_choices = [
        'Steve biko Campus',
        'Ritson Campus',
        'ML Sultan Campus',
        'City Campus',
        'Indumiso Campus',
        'Midlands Campus',
        'Brickfield Campus'
    ]

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        camp_name = request.form['camp_name']

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if role == 'Admin' and is_admin_in_campus(camp_name):
            flash('There is already an admin for this department.', 'danger')
            return redirect(url_for('register'))
        if existing_user:
            flash('Username or email already exists. Please choose another.', 'danger')
        else:
            user = User(username=username, email=email, password=generate_password_hash(password), role=role, camp_name=camp_name)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', campus_choices=campus_choices, title=title)

def is_admin_in_campus(camp_name):
    existing_admin = User.query.filter_by(camp_name=camp_name, role='Admin').first()
    return existing_admin is not None

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def login():
    title = 'Login'
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                flash('Login successful', 'success')
                return redirect(get_redirect_url(user))
            else:
                flash('Incorrect password. Please check your credentials.', 'danger')
        else:
            flash('User not found. Please check your username.', 'danger')
    return render_template('login.html', title=title)

def get_redirect_url(user):
    if user.role == 'Admin':
        return url_for('admin_bookings')
    else:
        return url_for('report')

@app.route('/user/report', methods=['GET', 'POST'])
@login_required
def report():
    title = 'Report'
    
    if request.method == 'POST':
        Campus = request.form['Campus']
        block = request.form['block']
        #user_campus = current_user.camp_name
        description = request.form['description'] if current_user.role == 'Student' else None
        #camp_block = get_block(user_campus)
       

        existing_reports = Reports.query.filter(
            Reports.user_id == current_user.id,
            Reports.Campus == Campus,
            Reports.block == block,
            Reports.description == description
        ).all()

        if existing_reports:
            flash('This issue is allready reported', 'danger')
            existing_reports = Reports.query.filter(
                Reports.user_id == current_user.id,
                Reports.description == description,
            ).first()

        else:
            new_report = Reports(user_id=current_user.id, Campus=Campus, block=block, description=description)
            db.session.add(new_report)
            db.session.commit()

            # user_email = current_user.email
            # booking_details = f"Lab Name: {lab_name}, Start Time: {slot_start_time}, End Time: {slot_end_time}"  # Replace with actual booking details
            # send_booking_confirmation(user_email, booking_details)

            flash('Report successful', 'success')

    report = Reports.query.filter_by(user_id=current_user.id).all()
    
    return render_template('report.html',  report=report, title=title)

def get_block(user_campus):
    block_mapping = {
        'Steve Biko Campus': 'Steve Block',
        'Ritson Campus': 'Ritson block',
        'ML Sultan Campus': 'ML Sultan block',
        'City Campus': 'City block',
        'Indumiso Campus': 'Indumiso block',
        'Midlands Campus': 'Midlands block',
        'Brickfield': 'Brickfield block',

    }
    return block_mapping.get(user_campus, None)

@app.route('/admin/bookings', methods=['GET'])
@login_required
def admin_bookings():
    title='Admin'
    if current_user.is_authenticated and current_user.role == 'Admin':
        admin_campus = current_user.camp_name
        report = Reports.query.join(User).filter(User.camp_name == admin_campus).all()
        return render_template('admin_bookings.html', report=report, title=title)
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

@app.route('/admin/admin_booking/<int:booking_id>', methods=['POST'])
@login_required
def accept_booking(booking_id):
    if current_user.is_authenticated and current_user.role == 'Admin':
        report = Reports.query.get(booking_id)

        if report:
            report.status = 'Accepted'
            db.session.commit()
            flash('Report has been accepted.', 'success')
        else:
            flash('Report not found.', 'danger')

    return redirect(url_for('admin_bookings'))

@app.route('/admin/admin_booking/<int:booking_id>', methods=['POST'])
@login_required
def decline_booking(booking_id):
    if current_user.is_authenticated and current_user.role == 'Admin':
        report = Reports.query.get(booking_id)

        if report:
            report.status = 'Declined'
            db.session.commit()
            flash('Report has been declined.', 'success')
        else:
            flash('Report not found.', 'danger')

    return redirect(url_for('admin_bookings'))

@app.route('/report/update/<int:booking_id>', methods=['GET', 'POST'])
@login_required
def update_booking(booking_id):
    title = 'Update Booking'
    report = Reports.query.get(booking_id)

    if not report:
        flash('Report not found.', 'danger')
        return redirect(url_for('report'))

    if current_user.id != report.user_id:
        flash('You do not have permission to update this booking.', 'danger')
        return redirect(url_for('report'))

    if request.method == 'POST':
        block = request.form['block']

        if current_user.role == 'Student':
            description = request.form['description']
        else:
           description = None

        report.block = block
        report.description = description

        db.session.commit()

        flash('Report updated successfully.', 'success')
        return redirect(url_for('report'))

    return render_template('update_booking.html', report=report, title=title)

@app.route('/report/delete/<int:booking_id>', methods=['POST'])
@login_required
def delete_booking(booking_id):
    report = Reports.query.get(booking_id)

    if not report:
        flash('report not found.', 'danger')
        return redirect(url_for('report'))

    if current_user.id != report.user_id:
        flash('You do not have permission to delete this report.', 'danger')
        return redirect(url_for('report'))

    db.session.delete(report)
    db.session.commit()

    flash('Report deleted successfully.', 'success')
    return redirect(url_for('report'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/view_report/<report_id>')
def view_report(report_id):
    if request.method == 'POST':
        Campus = request.form['Campus']
        block = request.form['block']
        #user_campus = current_user.camp_name
        description = request.form['description'] if current_user.role == 'Student' else None
        #camp_block = get_block(user_campus)
       
    
        existing_reports = Reports.query.filter(
            Reports.user_id == current_user.id,
            Reports.Campus == Campus,
            Reports.block == block,
            Reports.description == description
        ).all()
        if existing_reports:
            flash('This issue is allready reported', 'danger')
            existing_reports = Reports.query.filter(
                Reports.user_id == current_user.id,
                Reports.description == description,
            ).first()

        else:
            new_report = Reports(user_id=current_user.id, Campus=Campus, block=block, description=description)
            db.session.add(new_report)
            db.session.commit()

            # user_email = current_user.email
            # booking_details = f"Lab Name: {lab_name}, Start Time: {slot_start_time}, End Time: {slot_end_time}"  # Replace with actual booking details
            # send_booking_confirmation(user_email, booking_details)

            flash('Report successful', 'success')

    report = Reports.query.filter_by(user_id=current_user.id).all()
    
    return render_template('view_report.html',  report=report)
    # Logic to retrieve and display the report with the given ID
    #return f"This is the report with ID: {report_id}"

  
    


if __name__ == '__main__':
    app.run(debug=True)