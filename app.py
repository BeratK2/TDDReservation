from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, PasswordField, SubmitField, TimeField, IntegerField
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, NumberRange
import os
from datetime import datetime, timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# Set configurations before initializing the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
 # Triple slashes for relative path
app.config['SECRET_KEY'] = 'secretkey'

# Initialize the database after the config
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True, unique=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Restaurant(db.Model, UserMixin):
    __tablename__ = 'restaurant'

    id = db.Column(db.Integer, primary_key=True, unique=True)
    title = db.Column(db.String(80), primary_key=True)
    startTime = db.Column(db.String(80), nullable=False)
    endTime = db.Column(db.String(80), nullable=False)

class ReservationSlot(db.Model):
    __tablename__ = 'reservation_slot'

    id = db.Column(db.Integer, primary_key=True, unique=True)
    capacity = db.Column(db.Integer, nullable=False)

class Reservation(db.Model):
    __tablename__ = 'reservation'

    id = db.Column(db.Integer, primary_key=True, unique=True)
    name = db.Column(db.String(80), nullable=False)
    phone_number = db.Column(db.String(10), nullable=False)
    hour = db.Column(db.String(4), nullable=False)
    party_size = db.Column(db.Integer, nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

class RestaurantForm(FlaskForm):
    title = StringField('Restaurant Title', validators=[DataRequired()])
    startTime = TimeField('Start Time', format='%H:%M', validators=[DataRequired()])
    endTime = TimeField('End Time', format='%H:%M', validators=[DataRequired()])
    capacity = IntegerField('Number of seats', validators=[DataRequired(), NumberRange(min=0, max=999, message="Capacity must be between 0 and 999")])
    submit = SubmitField('Update')


@app.route('/')
def home():
    # Retrieve the timeSlots from query parameters
    timeSlots_str = request.args.get('timeSlots', '')
    timeSlots = timeSlots_str.split(',') if timeSlots_str else []
    
    # Retrieve the title of the restaurant from the database
    restaurant = Restaurant.query.first()  # Modify this query as needed
    restaurant_title = restaurant.title if restaurant else "No Restaurant Found"

    return render_template('home.html', timeSlots=timeSlots, restaurant_title=restaurant_title)

@app.route('/reservation/<hour>', methods=['GET', 'POST'])
def reservation(hour):
    # Extract the first two digits of the hour (e.g., "14:00" becomes "14")
    hour = hour[:2]

    # Get the capacity for the specific hour from the ReservationSlot table
    slot = ReservationSlot.query.filter_by(id=hour).first()
    
    # Check if the slot exists
    if slot:
        capacity = slot.capacity
        print("SLOT CAPACITY: " + str(capacity))
    else:
        capacity = 0  # Handle the case where the slot does not exist
        print("SLOT CAPACITY: " + str(capacity))

    # Check the number of reservations for this hour
    reservation_count = Reservation.query.filter_by(hour=hour).count()
    print("RESERVATION COUNT: " + str(reservation_count))

    # Handle form submission if it's a POST request
    if request.method == 'POST':
        print("POST REQUEST")
        name = request.form.get('name')
        phone = request.form.get('phone')
        party_size = request.form.get('party_size', type=int)

        # Validate party size (1 or more)
        if party_size < 1:
            flash('Party size must be at least 1!', 'error')
            return redirect(url_for('reservation', hour=hour))

        # Only proceed if there is capacity available
        if reservation_count < capacity:
            new_reservation = Reservation(name=name, phone_number=phone, hour=hour, party_size=party_size)
            db.session.add(new_reservation)
            db.session.commit()
            flash('Reservation submitted successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('This time slot is filled!', 'error')
            print("RESERVATION FULL")
            return redirect(url_for('home'))  # or redirect to an appropriate page

    return render_template('reservation.html', hour=hour, capacity=capacity, reservation_count=reservation_count)

@app.route('/submit_reservation', methods=['POST'])
def submit_reservation():
    # Retrieve form data
    name = request.form.get('name')
    phone = request.form.get('phone')
    party_size = request.form.get('party_size', type=int)  # This can remain but won't be validated
    hour = request.form.get('hour')

    # Extract the first two digits of the hour
    hour_short = hour[:2]  # e.g., "14:00" becomes "14"

    # Get the capacity for the specific hour from the ReservationSlot table
    slot = ReservationSlot.query.filter_by(id=hour_short).first()
    
    # Check if the slot exists and get its capacity
    if not slot:
        flash('Invalid time slot!', 'error')
        return redirect(url_for('home'))  # Redirect if the slot doesn't exist

    capacity = slot.capacity
    print("SLOT CAPACITY: " + str(capacity))

    # Check the number of reservations for this hour
    reservation_count = Reservation.query.filter_by(hour=hour_short).count()
    print("RESERVATION COUNT: " + str(reservation_count))

    # Check if reservation exceeds capacity
    if reservation_count >= capacity:
        flash('This time slot is filled!', 'error')
        print("RESERVATION FULL")
        return redirect(url_for('home'))

    # Create a new reservation instance
    new_reservation = Reservation(name=name, phone_number=phone, hour=hour_short, party_size=party_size)

    # Add the reservation to the session and commit
    db.session.add(new_reservation)
    db.session.commit()

    # Flash a message to confirm successful reservation
    flash('Reservation submitted successfully!', 'success')
    return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                print("Password is wrong")
                return render_template('login.html', form=form, invalid_credentials=True, message='Either your username and/or password is invalid. Please try again')
        else:
            print("Username is wrong")
            return render_template('login.html', form=form, invalid_credentials=True, message='Either your username and/or password is invalid. Please try again')


    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    duplicate_user = User.query.filter_by(username=form.username.data).first()
    if duplicate_user:
        return render_template('register.html', form=form, duplicate_user=True, message='A user with this username already exists, please choose another.')
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)    
        db.session.add(new_user) 
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = RestaurantForm()

    # Fetch the single restaurant (assuming only one exists)
    restaurant = Restaurant.query.first()
    ReservationSlot.query.delete()

    if form.validate_on_submit():
        startTime = form.startTime.data.strftime('%H:%M')
        endTime = form.endTime.data.strftime('%H:%M')
        newRestaurant = Restaurant(title=form.title.data, startTime=startTime, endTime=endTime)
        timeSlots = []
        reservation_slots = []

        # Loop through every hour between startTime and endTime
        current_time = datetime.strptime(startTime, "%H:%M")
        endTime = datetime.strptime(endTime, "%H:%M")
        
        while current_time <= endTime:
            # Append the time in 'HH:MM' format to timeSlots
            timeSlots.append(current_time.strftime('%H:%M'))
            reservation_slots.append(int(current_time.strftime('%H')))
            
            # Increment by one hour
            current_time += timedelta(hours=1)

        db.session.delete(restaurant)
        db.session.add(newRestaurant)

        for reservation_slot in reservation_slots:
            newReservationSlot = ReservationSlot(id=reservation_slot, capacity=form.capacity.data)
            db.session.add(newReservationSlot)

        db.session.commit()
        
        # Join timeSlots into a comma-separated string
        timeSlots_str = ','.join(timeSlots)

        # Redirect to the home route with query parameters
        return redirect(url_for('home', timeSlots=timeSlots_str))

    reservation_slot = ReservationSlot.query.first()

    # Pre-populate the form with the current values from the database
    if restaurant:
        form.title.data = restaurant.title
        form.startTime.data = datetime.strptime(restaurant.startTime, '%H:%M')
        form.endTime.data = datetime.strptime(restaurant.endTime, '%H:%M')

    if reservation_slot:
        form.capacity.data = reservation_slot.capacity

    # Query all reservations to display on the dashboard
    all_reservations = Reservation.query.all()

    return render_template('dashboard.html', form=form, reservations=all_reservations)




if __name__ == '__main__':
    app.run(debug=True)