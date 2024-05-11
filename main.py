from flask import Flask, render_template, url_for, request, redirect, session
from pymongo import MongoClient
import bcrypt

app = Flask(__name__) 
app.static_folder = 'static'
app.secret_key = 'farm_connect'

#connect to Mongo database
client = MongoClient('mongodb://localhost:27017')
db = client['farm']
collection = db['signup']

#bcrypt hashed passwords 
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

#route to signup page to create a new account
@app.route('/')
def signup():
    return render_template('signup.html')

#route to render login page when signup page is open 
@app.route('/loginpage')
def loginpage():
    return render_template('login.html')

#route to render signup page when login page is open 
@app.route('/signuppage')
def signuppage():
    return render_template('signup.html')

#route to fill the signup page and enter data into database
@app.route('/submit', methods=['POST'])
def submit():
    
    name =  request.form['name']
    email =  request.form['email']
    password =  request.form['password']
    
    #check if the email contains valid domain
    valid_domain = ['@seller.com', '@consumer.com']
    if not any(domain in email for domain in valid_domain):
        error_message = "Invalid domain! Please use @consumer.com or @seller.com"
        return render_template('signup.html', show_error = bool(error_message), error_message = error_message)
    
    #hashing the passwords into binary format 
    hashed_password = hash_password(password)
    
    #inserting the data into the database
    collection.insert_one({'name': name, 'email': email, 'password': hashed_password})

    return redirect(url_for('loginpage'))

#Code to run the consumer dashboard
@app.route('/consumer_dashboard')
def consumer_dashboard(): 
    return render_template('consumer.html')
    
#Code to run the seller dashboard
@app.route('/seller_dashboard')
def seller_dashboard():
    return render_template('seller.html')

#route to handle the logic authentication
@app.route('/loginauthentication', methods = ['POST'])
def loginauthentication():
    email =  request.form['email']
    password = request.form['password']
    user = collection.find_one({'email': email})
    error_message = None
    
    if user and verify_password (password, user['password']):
        session['email'] = email
        if '@consumer.com' in email:
            return redirect(url_for('consumer_dashboard'))
        elif '@seller.com' in email:
            return redirect(url_for('seller_dashboard'))
    else:
        error_message = "Invalid username or password. Please try again"
        
    return render_template('login.html', show_error = bool(error_message), error_message = error_message)
        
if __name__ == 'main':
    app.run(debug = False, host = ''0.0.0.0)
