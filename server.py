from flask import Flask, render_template, request, redirect, session, flash
app = Flask(__name__)
app.secret_key = 'zeyfletkey'
from mysqlconnection import MySQLConnector
import re, md5, os, binascii
mysql = MySQLConnector(app,'space_gameDB')


@app.route('/')
def index():
    return render_template('home.html')

@app.route('/register', methods=['POST'])
def register():
    username=request.form['username']
    password=request.form['password']
    first_name=request.form['first_name']
    validation = True
    password_regex = re.search(r'\d', password)
    password_regex2 = re.search(r'[A-Z]', password)
    if len(username) < 1 or len(first_name) < 1 or len(password) < 1 : #checking if fields are filled
        flash('Please fill out all fields')
        validation = False
    if not first_name.isalpha() or not username.isalpha(): #names should only be letters
        flash('Names and username should contain letter only' )
        validation = False
    if len(password) < 5: #validate if pass is 5 characters long
        flash('Password should be atleast 5 characters long')
        validation = False
    if not password_regex or not password_regex2: #confirm that password has least 1 uppercase letter and 1 numeric value
        flash('Password must contain number and uppercase letter')
        validation = False
    # if validation == True:
    #     flash('Thanks. You have registered!')
    if validation== True:
        salt = binascii.b2a_hex(os.urandom(15))
        hashed_pw = md5.new(password + salt).hexdigest()
        query = "insert into users (first_name, username, password, salt) values (:first_name, :username, :password, :salt);"
        data = {
            "first_name": first_name,
            "username": username,
            "password": hashed_pw,
            "salt": salt
        }
        user_id = mysql.query_db(query, data)
        session['user_id'] = user_id
        flash('Thanks. You have successfully registered!')
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    query = 'select * from users where username = :username;'
    data = {
		"username": request.form['username']
	}
    user = mysql.query_db(query, data)
    
    if len(user) > 0 and user[0]['password'] == md5.new(request.form['password'] + user[0]['salt']).hexdigest():
        session['user_id'] = user[0]['id']
        return render_template('/second_page.html', name=user[0]['first_name'])
    else:       	# query select didn't find any matching user submitted email, ie invalid login
		flash('Invalid login credentials...')
		return redirect('/')

@app.route('/home', methods=['POST'])
def home():
    return render_template('second_page.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/')

@app.route('/second_page/play', methods=['POST'])
def second_page():

    return render_template('game.html')
app.run(debug=True)
