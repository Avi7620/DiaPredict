from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_mail import Mail, Message
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import pickle
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prediction222.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.secret_key = 'your_secret_key_here'

# Configure Flask Mail
app.config['MAIL_SERVER'] = 'smtp.fastmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'avinash7620@fastmail.com'
app.config['MAIL_PASSWORD'] = '4r273r4k5b722g48'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

# Load your machine learning model
model = pickle.load(open('C:/Users/Lenovo/Pictures/predict_diabetes/model.pkl', 'rb'))

# Load the dataset
dataset = pd.read_csv('C:/Users/Lenovo/Pictures/predict_diabetes/diabetes.csv')
dataset_X = dataset.iloc[:, [1, 2, 5, 7]].values

# Scale the dataset
sc = MinMaxScaler(feature_range=(0, 1))
dataset_scaled = sc.fit_transform(dataset_X)

#----------------------------------------------------------- Tables -------------------------------------------------------------------------------------

#prediction store table
#prediction store table
# Updated Prediction model
class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Glucose_Level = db.Column(db.Float, nullable=False)
    Insulin = db.Column(db.Float, nullable=False)
    BMI = db.Column(db.Float, nullable=False)
    Age = db.Column(db.Float, nullable=False)
    Prediction_Result = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('predictions', lazy=True))

    def __repr__(self):
        return f"Prediction(Glucose_Level={self.Glucose_Level}, Insulin={self.Insulin}, BMI={self.BMI}, Age={self.Age}, Prediction_Result={self.Prediction_Result}, User={self.user.username})"

#user table
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
    
#contact table
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)


#--------- main predict function ------------
@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        # Retrieve form data
        Glucose_Level = float(request.form['Glucose Level'])
        Insulin = float(request.form['Insulin'])
        BMI = float(request.form['BMI'])
        Age = float(request.form['Age'])

        # Prepare features for prediction
        features = np.array([[Glucose_Level, Insulin, BMI, Age]])

        # Transform features using scaler (if any)
        features_scaled = sc.transform(features)

        # Make prediction using the model
        prediction = model.predict(features_scaled)

        # Process prediction result
        if prediction == 1:
            pred_result = "You may have Diabetes, please consult a Doctor."
            send_email()
            show_button = True  # Set show_button to True
        else:
            pred_result = "You may not have Diabetes."
            send_email2()
            show_button = False  # Set show_button to False

        # Retrieve the logged-in user
        user = User.query.filter_by(email=session['email']).first()

        # Store prediction result in the database
        prediction_record = Prediction(
            Glucose_Level=Glucose_Level,
            Insulin=Insulin,
            BMI=BMI,
            Age=Age,
            Prediction_Result=pred_result,
            user_id=user.id  # Associate prediction with user
        )
        db.session.add(prediction_record)
        db.session.commit()

        return render_template('index.html', prediction_text=pred_result, show_button=show_button)


#------------------------------------------- show prediction result --------------------------------------

@app.route('/user_predictions')
def user_predictions():
    # Fetch all users and their predictions
    users_with_predictions = User.query.join(Prediction).all()

    # Extract predictions from all users
    all_predictions = []
    for user in users_with_predictions:
        all_predictions.extend(user.predictions)

    return render_template('user_predictions.html', predictions=all_predictions)



#------------------------------------------------------------ all routes ----------------------------------------------------
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/search')
def search():
    return render_template('search.html')

@app.route('/')
def main():
    return render_template('smain.html')

@app.route('/smain')
def smain():
    return render_template('smain.html')

@app.route('/adminlogin')
def adminlogin():
    return render_template('adminlogin.html')

@app.route('/slogin2')
def slogin2():
    return render_template('slogin.html') 

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for('main'))

#------------------------------------------------------------------ email ----------------------------------------------------------------------
#prediction==1
#prediction==1
def send_email():
    recipient_email = session['email']  # Retrieve email from session
    msg = Message("Diabetes Prediction Result", 
                  sender=app.config['MAIL_USERNAME'],  # Ensure the sender email matches the authenticated email
                  recipients=[recipient_email])
    msg1 = 'You may have Diabetes, please consult a Doctor. To get a Doctor appointment visit https://www.practo.com/consult'
    msg.body = f"{msg1}"
    mail.send(msg)

#prediction==0
def send_email2():
    recipient_email = session['email']  # Retrieve email from session
    msg = Message("Diabetes Prediction Result", 
                  sender=app.config['MAIL_USERNAME'],  # Ensure the sender email matches the authenticated email
                  recipients=[recipient_email])
    msg2 = 'You may not have Diabetes. To get a Doctor appointment visit https://www.practo.com/consult'
    msg.body = f"{msg2}"
    mail.send(msg)

  
#------------------------------admin login and user login / signup------------------------------------------------------------------------------------

#admin login
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_username = request.form['admin_username']
        admin_password = request.form['admin_password']
        
        # Check if the entered credentials match the hardcoded values
        if admin_username == 'admin' and admin_password == 'admin':
             # Store admin username in the session
            return redirect(url_for('contacts'))  # Redirect to admin dashboard
        else:
            return render_template('adminlogin.html', message='Invalid admin username or password.')
    else:
        return render_template('adminlogin.html')

#login
@app.route('/slogin', methods=['POST'])
def slogin():
    email = request.form['email']
    password = request.form['pswd']

    user = User.query.filter_by(email=email, password=password).first()

    if user:
        session['email'] = email  # Set email in the session
        flash("Login successful!", 'success')
        return redirect(url_for('index'))
    else:
        flash("Invalid email or password.", 'error')
        return redirect(url_for('slogin2'))

#signup
@app.route('/ssignup', methods=['POST'])
def ssignup():
    username = request.form['txt']
    email = request.form['email']
    password = request.form['pswd']
    reenter_password = request.form['reenter_pswd']

    if password != reenter_password:
        flash("Passwords do not match. Please try again.", 'error')
        return redirect(url_for('slogin2'))

    if User.query.filter_by(email=email).first():
        flash("Email already exists. Please use another email.", 'error')
        return redirect(url_for('slogin2'))

    new_user = User(username=username, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    session['email'] = email  # Set email in the session

    flash("Signup successful!", 'success')
    return redirect(url_for('slogin2'))

#-------------------------------------------------------------------prediction show and delete ---------------------------------------------------
@app.route('/delete_prediction/<int:prediction_id>', methods=['DELETE'])
def delete_prediction(prediction_id):
    prediction = Prediction.query.get(prediction_id)
    if prediction:
        db.session.delete(prediction)
        db.session.commit()
        return 'Prediction deleted successfully', 200
    else:
        return 'Prediction not found', 404

@app.route('/show_predictions')
def show_predictions():
    # Retrieve predictions from the database
    predictions = Prediction.query.all()
    return render_template('predictions.html', predictions=predictions)

#----------------------------------------------------------------------show and delte contact------------------------------------------------------
@app.route('/contact', methods=['POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        # Create a new Contact object
        new_contact = Contact(name=name, email=email, message=message)
        
        # Add the object to the database
        db.session.add(new_contact)
        db.session.commit()
        
        # Fetch all contacts from the database
        contacts = Contact.query.all()
        
        
        return redirect(url_for('smain', contacts=contacts))
    
@app.route('/delete_contact/<int:contact_id>', methods=['POST'])
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    db.session.delete(contact)
    db.session.commit()
    flash('Contact deleted successfully!', 'success')
    return redirect(url_for('contacts'))

@app.route('/contacts')
def contacts():
    # Fetch all contacts from the database
    contacts = Contact.query.all()
    
    return render_template('contacts.html', contacts=contacts)

import secrets
from flask import request, url_for

# Generate a unique token for password reset
token = secrets.token_urlsafe(16)

# Send password reset email
from flask import render_template, request, url_for, redirect

# Forgot password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a reset token
            token = generate_reset_token()  # You need to define this function
            user.reset_token = token  # Save token in the user's record
            db.session.commit()
            
            # Construct the reset password URL
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Send email with reset URL
            send_reset_email(email, reset_url)  # You need to define this function
            
            return 'Password reset email sent successfully'
        else:
            return 'Email not found'
    else:
        return render_template('forgot_password.html')

# Reset password route
from flask import redirect

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['password']
        # Update user's password
        user = User.query.filter_by(reset_token=token).first()
        if user:
            user.password = new_password
            user.reset_token = None  # Clear reset token
            db.session.commit()
            flash('Password reset successfully!', 'success')
            return redirect(url_for('slogin'))  # Redirect to the login route
        else:
            flash('Invalid or expired token', 'error')
            return redirect(url_for('slogin2'))  # Redirect to the login page with error message
    else:
        return render_template('reset_password.html')


import secrets

def generate_reset_token():
    """
    Generate a unique reset token.
    """
    return secrets.token_urlsafe(16)  # Generate a URL-safe token with 16 bytes of randomness



def send_reset_email(user_email, reset_url):
    """
    Send a password reset email to the user.
    """
    msg = Message('Password Reset Request', sender='avinash7620@fastmail.com', recipients=[user_email])
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.
'''
    mail.send(msg)


with app.app_context():
    db.create_all()
if __name__ == '__main__':
   
    app.run(debug=True, port=8000)
