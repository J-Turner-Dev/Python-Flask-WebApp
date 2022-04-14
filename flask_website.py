"""
__filename__ = "flask_webpsite.py"
__coursename__ = "SDEV 300 6381 - Building Secure Python Applications (2208)"
__professor__ = "Dr. Jason Cohen"
__author__ = "Joshua Turner"
__copyright__ = "None"
__credits__ = ["Joshua Turner"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Joshua Turner"
__email__ = "JTURNER160@student.umgc.edu"
__status__ = "Production"
__purpose__ = "Build a website using flask to render html templates and add functionality"

"""
import datetime
import os
from flask import Flask, render_template, redirect, url_for, request, session
from flask_bcrypt import Bcrypt

APP = Flask(__name__)
bcrypt = Bcrypt(APP)
APP.secret_key = b'\x92o\xc2\x81\xef\x83\xc91a\xe5\x8axw*\x9c\xd6'


def current_date_time():
    """returns the date and time when called"""
    return str(datetime.datetime.today().ctime())


def password_is_valid(password):
    """Checks for proper password format for new passwords"""
    alpha_upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    alpha_lower = 'abcdefghijklmnopqrstuvwxyz'
    numbers = '0123456789'
    special_characters = '!@#$%^&*()+=_-.?[]~`:;'
    conditions = {'upper': 0, 'lower': 0, 'number': 0, 'special': 0}
    if len(password) < 12:
        return 'false_length'
    for element in password:
        if element in alpha_upper:
            conditions['upper'] += 1
        elif element in alpha_lower:
            conditions['lower'] += 1
        elif element in numbers:
            conditions['number'] += 1
        elif element in special_characters:
            conditions['special'] += 1
        else:
            return 'false_character'
    for value in conditions.values():
        if value == 0:
            return 'false_complexity'
    return 'true'


def bad_password_message(fail_string):
    """Returns a message according to why the password was wrong"""
    if fail_string == 'false_length':
        return "Password must be atleast 12 characters long.\nEnter a different Password."
    if fail_string == 'false_character':
        return "Password contains an invalid character.\nEnter a different Password."
    if fail_string == 'false_complexity':
        return "Password must contain atleast one of each: an upper case and a lower case letter, \
                number, and a symbol.\nEnter a different Password."


def username_is_valid(username):
    """Checks the username for valid characters"""
    characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-'
    for character in username:
        if character not in characters:
            return False
    return True


def add_user(user_name, pass_word, nick_name):
    """Adds a new account registered for the website"""
    database = open('database.txt', 'a+')
    with database:
        for account in database:
            username, password, name = account.split()
            if user_name == username:
                database.close()
                return 0
        database.write(user_name + " " + bcrypt.generate_password_hash(
            pass_word).decode('utf-8') + " " + nick_name + "\n")
        database.close()
        return 1


def change_password(user_name, new_password):
    """Updates the users olde password with a new one"""
    database = open('database.txt')
    temp_database = open('temp_database.txt', 'w+')
    with database, temp_database:
        for account in database:
            username, password, name = account.split()
            if user_name != username:
                temp_database.write(account)
            else:
                update_account = ' '.join([username, bcrypt.generate_password_hash(
                    new_password).decode('utf-8'), name])
                temp_database.write(update_account + '\n')
        database.close()
        temp_database.close()
        os.remove('database.txt')
        os.rename('temp_database.txt', 'database.txt')


def check_password(user_name, pass_word):
    """Matches the password entered for one on file"""
    database = open('database.txt', 'r+')
    with database:
        for account in database:
            username, password, name = account.split()
            print(username + ' ' + user_name)
            if user_name.strip() == username.strip():
                if bcrypt.check_password_hash(password, pass_word):
                    database.close()
                    return 1
                database.close()
                return 0
            database.close()
            return -1


def return_nick_name(user_name):
    """Checks for the name of the user and returns it"""
    database = open('database.txt', 'r')
    with database:
        for account in database:
            username, password, name = account.split()
            if user_name == username:
                database.close()
                return name
    database.close()
    return 'false'


def check_common_passwords(pass_word):
    """Checks password against list of commonly used passwords"""
    passwords = open('CommonPassword.txt', 'r')
    with passwords:
        for password in passwords:
            if pass_word == password.strip():
                passwords.close()
                return True
    passwords.close()
    return False


@APP.route('/', methods=['POST', 'GET'])
def login():
    """renders the login page"""
    message = request.args.get('login_message', None)
    if message is None:
        message = "Welcome to Chess Theory!"

    if request.method == 'POST':
        user_name = request.form['un']
        pass_word = request.form['pw']
        password_valid = check_password(user_name, pass_word)
        if password_valid == 1:
            session['user'] = (user_name, return_nick_name(user_name))
            print(session['user'])
            return redirect(url_for('home'))
        if password_valid == 0:
            ip_address = request.remote_addr
            fail_time = current_date_time()
            log_string = (fail_time + " " + user_name + " " + pass_word + "\n")
            with open('failed_login.txt', 'a+') as fail_log:
                fail_log.write(ip_address)
                fail_log.write(log_string)
            message = "Password Incorrect! Enter correct password."
            return render_template('chess_login.html', login_message=message)
        if password_valid == -1:
            ip_address = request.remote_addr
            fail_time = current_date_time()
            log_string = (fail_time + " " + user_name + " " + pass_word + "\n")
            with open('failed_login.txt', 'a+') as fail_log:
                fail_log.write(ip_address)
                fail_log.write(log_string)
            message = "User not found! Register new user."
            return render_template('chess_login.html', login_message=message)

    if 'user' in session:
        return redirect(url_for('home'))
    return render_template('chess_login.html', login_message=message)


@APP.route('/registration', methods=['POST', 'GET'])
def registration():
    """renders the registration page"""
    message = "Register to login to Chess Theory"
    if request.method == 'POST':
        nick_name = request.form['nm']
        user_name = request.form['un']
        pass_word = request.form['pw']
        if username_is_valid(user_name):
            if check_common_passwords(pass_word):
                message = "Password is a commonly used password. Use a more complex password"
                return render_template('chess_registration.html', registration_message=message)
            valid_password = password_is_valid(pass_word)
            if valid_password == 'true':
                valid_entry = add_user(user_name, pass_word, nick_name)
                print(valid_entry)
                if valid_entry == 0:
                    message = "Username already in database. Select new Username."
                    return render_template('chess_registration.html', registration_message=message)
                if valid_entry == 1:
                    message = "Registration complete. Now log in."
                    return redirect(url_for('login', login_message=message))
            else:
                message = bad_password_message(valid_password)
                return render_template('chess_registration.html', registration_message=message)
        else:
            message = "Username contains invalid characters. Use Letters, \
                        Numbers, period, underscore, or dash only."
            return render_template('chess_registration.html', registration_message=message)
    return render_template('chess_registration.html', registration_message=message)


@APP.route('/password_update', methods=['POST', 'GET'])
def password_update():
    """renders the update password page"""
    if 'user' in session:
        message = "Update your password."
        if request.method == 'POST':
            old_password = request.form['op']
            new_password = request.form['np']
            user_name = session['user'][0]
            password_match = check_password(user_name, old_password)
            if password_match == 1:
                if check_common_passwords(new_password):
                    message = "Password is a commonly used password. Use a more complex password"
                    return render_template('password_update.html', update_message=message)
                password_valid = password_is_valid(new_password)
                if password_valid == 'true':
                    change_password(user_name, new_password)
                    return redirect(url_for('home'))
                message = bad_password_message(password_valid)
                return render_template('password_update.html', update_message=message)
            if password_match == 0:
                message = "Old password does not match re-enter password."
                return render_template('password_update.html', update_message=message)
        return render_template('password_update.html', update_message=message)
    return redirect(url_for('login'))


@APP.route('/home')
def home():
    """renders the home html template and pass in the datetime"""
    if 'user' in session:
        return render_template('chess_main.html', time_passed_in=current_date_time(),
                               current_user=session['user'][1])
    return redirect(url_for('login'))


@APP.route('/sicilian_defense')
def sicilian_defense():
    """renders the sicilian defense html"""
    if 'user' in session:
        return render_template('sicilian_defense.html', current_user=session['user'][1])
    return redirect(url_for('login'))


@APP.route('/open_defense')
def open_defense():
    """renders the open defense html"""
    if 'user' in session:
        return render_template('open_defense.html', current_user=session['user'][1])
    return redirect(url_for('login'))


@APP.route('/french_defense')
def french_defense():
    """renders the french defense html"""
    if 'user' in session:
        return render_template('french_defense.html', current_user=session['user'][1])
    return redirect(url_for('login'))


@APP.route('/logout')
def logout():
    """Logs out of current user session"""
    session.pop('user', None)
    return redirect(url_for('login'))


if __name__ == "__main__":
    APP.run(debug=False)
