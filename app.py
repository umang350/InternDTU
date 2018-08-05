from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from threading import Thread
import datetime

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'some key'

# git clone https://github.com/umang350/flaskblogsip.git
# mysql -h flasktest.ccrvuveqgzmp.ap-south-1.rds.amazonaws.com -u umang350root -p flasktest

# Config MySQL
app.config['MYSQL_HOST'] = 'rds host'
app.config['MYSQL_USER'] = 'user'
app.config['MYSQL_PASSWORD'] = 'pass'

# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'admin'
app.config['MYSQL_DB'] = 'flasktest'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.config['MAIL_SERVER'] = 'smtp.zoho.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = 0
app.config['MAIL_USE_SSL'] = 1
app.config['MAIL_USERNAME'] = 'email'
app.config['MAIL_PASSWORD'] = 'pass'
app.config['MAIL_DEFAULT_SENDER'] = 'InternDTU@ecelldtu.in'
# init MySQL
mysql = MySQL(app)
mail = Mail(app)

def send_async_email(msg):
    with app.app_context():
        mail.send(msg)
        
def send_email(subject, recipients, text_body, html_body):
    msg = Message(subject, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    thr = Thread(target=send_async_email, args=[msg])
    thr.start()

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/internships')
def internships():
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM articles ORDER BY id DESC;")
    articles= cur.fetchall()
    if(result>0):
        return render_template('articles.html', articles = articles)
    else:
        msg ='No articles found'
        return render_template('articles.html', msg = msg)
    cur.close()

@app.route('/viewapplications/<string:id>/')
def viewapplications(id):
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM application INNER JOIN details ON application.username = details.username WHERE application.internship_id = %s;",([id]))
    articles= cur.fetchall()
    if(result>0):
        return render_template('viewapplications.html', articles = articles)
    else:
        msg = "No applications found for Internship ID : " + id
        flash(msg, 'danger')
        return redirect(url_for('dashboard'))
    cur.close()

@app.route('/viewusersall-admin')
def viewusersall():
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM users LEFT JOIN details ON users.username = details.username order by users.id;")
    articles= cur.fetchall()
    if(result>0):
        return render_template('viewusers.html', articles = articles)
    else:
        msg = "No users found "
        flash(msg, 'danger')
        return redirect(url_for('login'))
    cur.close()

@app.route('/viewcompanyall')
def viewcompanyall():
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM users WHERE users.isadmin = 1 order by users.id;")
    articles= cur.fetchall()
    if(result>0):
        return render_template('viewusers.html', articles = articles)
    else:
        msg = "No users found "
        flash(msg, 'danger')
        return redirect(url_for('login'))
    cur.close()

@app.route('/internship/<string:id>/')
def internship(id):
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article= cur.fetchone()
    return render_template('article.html', article = article)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = confirm_serializer.loads(token, salt='email-confirmation-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM users WHERE email = %s", [email])
    user = cur.fetchone()

    if user['email_confirmed']:
        flash('Account already confirmed. Please login.', 'info')
    else:
        cur.execute("UPDATE users SET email_confirmed = %s, email_confirmed_on = %s WHERE email = %s;", [1 , str(datetime.datetime.now()),  email])
        flash('Thank you for confirming your email address!', 'success')
        mysql.connection.commit()
        cur.close()

    return redirect(url_for('login'))

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    mobile = StringField('Mobile', [validators.Length(min=10, max=13)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message = 'Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email= form.email.data.lower()
        username = form.username.data.lower()
        mobile = form.mobile.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE email = %s or username = %s", [email, username])
        if(result>0):
            flash('User Exists with Similar Email or Username', 'danger')
            return redirect(url_for('register'))

        send_confirmation_email(email)
        

        cur.execute("INSERT INTO users(name, email, username, password, mobile) VALUES(%s, %s, %s, %s, %s)", (name, email, username, password, mobile))

        mysql.connection.commit()
        
        
        flash('Thanks for registering!  Please check your email to confirm your email address.', 'success')
        return redirect(url_for('login'))
        cur.close()

    return render_template('register.html', form = form)


def send_confirmation_email(user_email):
    confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token=confirm_serializer.dumps(user_email, salt='email-confirmation-salt')
 
    confirm_url = 'http://www.intern.ecelldtu.in/confirm/' + token
 
    html = render_template('email_confirmation.html', confirm_url=confirm_url)
 
    send_email('Confirm Your Email Address for InternDTU', [user_email], 'Your account on ECELL DTU Internship Portal was successfully created. Please click the link below to confirm your email address and activate your account:', html)

class RegisterCom(Form):
    name = StringField('Company Name (Will be visible in Internship listings)', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=100)])
    mobile = StringField('Mobile', [validators.Length(min=10, max=13)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message = 'Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')




@app.route('/registercompany', methods=['GET','POST'])
def registercompany():
    form = RegisterCom(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email= form.email.data.lower()
        username = form.username.data.lower()
        mobile = form.mobile.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE email = %s or username = %s", [email, username])
        if(result>0):
            flash('User Exists with Similar Email or Username', 'danger')
            return redirect(url_for('registercompany'))

        send_confirmation_email(email)

        cur.execute("INSERT INTO users(name, email, username, password, isadmin, mobile, resume) VALUES(%s, %s, %s, %s, %s, %s, %s)", (name, email, username, password, 1, mobile, 1))

        mysql.connection.commit()
        cur.close()
        
        flash('Thanks for registering!  Please check your email to confirm your email address.', 'success')
        return redirect(url_for('login'))
    return render_template('registercom.html', form = form)

class EmailForm(Form):
    email = StringField('Email', [validators.Length(min=6, max=50)])

def send_password_reset_email(user_email):
    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token = password_reset_serializer.dumps(user_email, salt='password-reset-salt')
    password_reset_url = 'http://www.intern.ecelldtu.in/reset/' + token
 
    html = render_template('email_password_reset.html', password_reset_url=password_reset_url)
 
    send_email('Password Reset Requested for InternDTU', [user_email], "You requested that the password for your ECELL DTU Internship Portal (InternDTU) account be reset. Please click the link below to reset your password:", html)


#USer logging
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form fields
        username = request.form['username'].lower()
        password_candidate = request.form['password']

        # create cursor
        cur = mysql.connection.cursor()

        # get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            isadmin = data['isadmin']
            resume = data['resume']
            email = data['email'].lower()
            name = data['name']
            
            #compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                if data['email_confirmed'] == 0:
                    send_confirmation_email(email)
                    error = 'Kindly confirm email Id'
                    return render_template('login.html', error= error)
                # passed
                session['logged_in'] = True
                session['username'] = username
                session['isadmin'] = isadmin
                session['email'] = email
                session['name'] = name
                session['resume'] = resume

                flash('You are now logged in', 'success')
                if(resume == 0 and isadmin == 0):
                    return redirect(url_for('details'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Login'
                return render_template('login.html', error= error)
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error= error)
    return render_template('login.html')

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized. Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

class PasswordForm(Form):
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message = 'Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/reset/<token>', methods=["GET", "POST"])
def reset_with_token(token):
    try:
        password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    form = PasswordForm(request.form)
 
    if request.method == 'POST' and form.validate():
        cur = mysql.connection.cursor()
        # get user by username
        password = sha256_crypt.encrypt(str(form.password.data))
        result = cur.execute("SELECT * FROM users WHERE email = %s", [email])
        article = cur.fetchone()
        if result > 0:
            cur.execute("UPDATE users SET password = %s WHERE email = %s; ", [password, email])
            mysql.connection.commit()
            cur.close()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid email address!', 'error')
            return render_template('password_reset_email.html', form=form) 
    return render_template('reset_password_with_token.html', form=form, token=token)

@app.route('/reset', methods=["GET", "POST"])
def reset():
    form = EmailForm(request.form)
    if request.method == 'POST' and form.validate():
        email=form.email.data.lower()
        cur = mysql.connection.cursor()

        # get user by username
        result = cur.execute("SELECT * FROM users WHERE email = %s", [email])
        article = cur.fetchone()
        if result > 0:
            if article['email_confirmed']:
                send_password_reset_email(email)
                flash('Please check your email for a password reset link.', 'success')
            else:
                flash('Your email address must be confirmed before attempting a password reset.', 'danger')
            return redirect(url_for('login'))
        else:
            flash('Invalid email address!', 'error')
            return render_template('password_reset_email.html', form=form)
    return render_template('password_reset_email.html', form=form)

@app.route('/resetadminumang/<id>', methods=["GET", "POST"])
def resetadminumang(id):
    form = PasswordForm(request.form)
 
    if request.method == 'POST' and form.validate():
        cur = mysql.connection.cursor()
        # get user by username
        password = sha256_crypt.encrypt(str(form.password.data))
        result = cur.execute("SELECT * FROM users WHERE id = %s", [id])
        article = cur.fetchone()
        if result > 0:
            cur.execute("UPDATE users SET password = %s, email_confirmed = %s WHERE id = %s; ", [password, 1, id])
            mysql.connection.commit()
            cur.close()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid email address!', 'error')
            return render_template('password_reset_email.html', form=form) 
    return render_template('reset_password_with_id.html', form=form, id=id)

class DetailsForm(Form):
    title = StringField('Title :', [validators.Length(min=1, max=200)])
    body = TextAreaField('About Yourself :', [validators.Length(min=1)])
    skills = StringField('Skills :', [validators.Length(min=1, max=200)])
    grade = StringField('Grade / CGPA :', [validators.Length(min=1, max=200)])  
    branch = StringField('Branch, Roll No. :', [validators.Length(min=1, max=200)])
    year = StringField('Year :', [validators.Length(min=1, max=10)])  

@app.route('/details', methods = ['GET', 'POST'])
@is_logged_in
def details():
    form = DetailsForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        skills = form.skills.data
        grade = form.grade.data
        branch = form.branch.data
        year = form.year.data

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM details WHERE username = %s", [session['username']])
        result1 = cur.execute("SELECT mobile FROM users WHERE username = %s", [session['username']])
        data = cur.fetchone()
        if(result>0):
            flash('Details Filled Already', 'danger')
            return redirect(url_for('dashboard'))

        cur.execute("INSERT INTO details(title, body, skills, grade, username, name, mobile, email, branch, year) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",(title, body, skills, grade, session['username'], session['name'], data['mobile'], session['email'], branch, year))
        cur.execute("UPDATE users SET resume = 1 WHERE username = %s; ", [session['username']])
        mysql.connection.commit()

        cur.close()

        flash('Resume Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('details.html', form = form)

@app.route('/edit_details', methods = ['GET', 'POST'])
@is_logged_in
def edit_details():
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM details WHERE username = %s", [session['username']])
    article= cur.fetchone()
    form = DetailsForm(request.form)

    form.title.data = article['title']
    form.body.data = article['body']
    form.skills.data = article['skills']
    form.grade.data = article['grade']
    form.branch.data = article['branch']
    form.year.data = article['year']

    if(article['username'] != session['username']):
        flash('Invalid Edit Request', 'danger')
        return redirect(url_for('dashboard'))


    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']
        skills = request.form['skills']
        grade = request.form['grade']
        branch = request.form['branch']
        year = request.form['year']

        cur = mysql.connection.cursor()

        cur.execute("UPDATE details SET title=%s, body = %s, skills = %s, grade = %s, branch = %s, year = %s WHERE username = %s", (title, body, skills, grade, branch, year, session['username']))
        mysql.connection.commit()

        cur.close()

        flash('Details Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_details.html', form = form)


@app.route('/dashboard')
@is_logged_in
def dashboard():
    cur = mysql.connection.cursor()
    if(session['isadmin'] == 1):
        result = cur.execute("SELECT * FROM articles WHERE company = %s or company = %s",[session["name"], session["username"]])
        articles = cur.fetchall()
        if(result>0):
            return render_template('dashboard.html', articles = articles)
        else:
            msg ='No Internship Posted found'
            return render_template('dashboard.html', msg = msg)
        cur.close()
    else:
        result = cur.execute("SELECT * FROM details WHERE username = %s",[session["username"]])
        data = cur.fetchone()
        if(result>0):
            return render_template('dashboard.html', data = data)
        else:
            msg ='No Details found Kindly go to /details'
            return redirect(url_for('details'))
        cur.close()

class ArticleForm(Form):
    profile = StringField('Profile Information', [validators.Length(min=1, max=500)])
    title = StringField('Intern Title', [validators.Length(min=1, max=200)])
    skills = StringField('Skills', [validators.Length(min=1, max=200)])
    grade = StringField('Stipend', [validators.Length(min=1, max=500)])
    info = StringField('About the Company (Website/ Links)', [validators.Length(min=1, max=200)])

@app.route('/add_internship', methods = ['GET', 'POST'])
@is_logged_in
def add_internship():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        profile = form.profile.data
        skills = form.skills.data
        grade = form.grade.data
        info = form.info.data
        

        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO articles(profile, title, company, skills, grade, info) VALUES(%s, %s, %s, %s, %s, %s)",(profile, title, session['name'], skills, grade, info))

        mysql.connection.commit()

        cur.close()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form = form)

class ApplyForm(Form):
    whyhire = StringField('Why should the company Hire you?', [validators.Length(min=1, max=200)])
    prevexp = StringField('Any Previous Experience related to the profile?', [validators.Length(min=1, max=200)])
    skillsrelated = StringField('List out your Skills Related to this profile :', [validators.Length(min=1, max=200)])
    other = StringField('Any other info you want to share?', [validators.Length(min=1, max=200)])

@app.route('/apply/<string:id>', methods = ['GET', 'POST'])
@is_logged_in
def apply(id):
    form = ApplyForm(request.form)
    if session['resume'] == 0:
            flash('Kindly fill details before applying', 'success')
            return redirect(url_for('details'))
    if request.method == 'POST' and form.validate() and session['isadmin'] == 0:
        whyhire = form.whyhire.data
        prevexp = form.prevexp.data
        skillsrelated = form.skillsrelated.data  
        other = form.other.data      

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM application WHERE username = %s AND internship_id = %s", [session['username'], id])
        if(result>0):
            flash('Already Applied in this Internship', 'danger')
            return redirect(url_for('dashboard'))

        cur.execute("INSERT INTO application(internship_id, username, whyhire, prevexp, skillsrelated, other) VALUES(%s, %s, %s, %s, %s, %s)",(id, session['username'], whyhire, prevexp, skillsrelated, other))

        mysql.connection.commit()

        cur.close()

        flash('Applied Successfully', 'success')

        return redirect(url_for('dashboard'))
    elif request.method == 'POST' and session['isadmin'] == 1:
        flash('Organisations cannot apply', 'danger')
        return redirect(url_for('dashboard'))
    
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article= cur.fetchone()
        
    return render_template('apply.html', article = article, form = form)

class QuizForm(Form):
    name = StringField('Name : ', [validators.Length(min=1, max=200)])
    ans = StringField('Answer to Current Question on the Screen :', [validators.Length(min=1, max=200)])
    mobile = StringField('Mobile No :', [validators.Length(min=1, max=200)])
    email = StringField('Email Id : ', [validators.Length(min=1, max=200)])

@app.route('/quiz', methods = ['GET', 'POST'])
@is_logged_in
def quiz():
    form = QuizForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        ans = form.ans.data
        mobile = form.mobile.data  
        email = form.email.data      

        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO quiz(name, username, ans, mobile, email) VALUES(%s, %s, %s, %s, %s)",(name, session['username'], ans, mobile, email))

        mysql.connection.commit()

        cur.close()

        flash('Question Answered Successfully get Ready for the Next Question!', 'success')

        return redirect(url_for('quiz'))
        
    return render_template('quiz.html', form = form)

@app.route('/viewquiz')
@is_logged_in
def viewquiz():
    cur = mysql.connection.cursor()
    if session['isadmin'] != 1:
        flash('Invalid Access!', 'danger')
        return redirect('/login')

    result = cur.execute("SELECT * FROM quiz order by id;")
    articles= cur.fetchall()
    return render_template('viewquiz.html', articles = articles)
    cur.close()

@app.route('/edit_internship/<string:id>', methods = ['GET', 'POST'])
@is_logged_in
def edit_internship(id):
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article= cur.fetchone()
    form = ArticleForm(request.form)

    form.title.data = article['title']
    form.profile.data = article['profile']
    form.skills.data = article['skills']
    form.grade.data = article['grade']
    form.info.data = article['info']
    cur.close()
    if(article['company'].lower() != session['name'].lower() and article['company'].lower() != session['username'].lower()):
        flash('Invalid Edit Request', 'danger')
        return redirect(url_for('dashboard'))


    if request.method == 'POST' and form.validate():
        title = request.form['title']
        profile = request.form['profile']
        skills = request.form['skills']
        grade = request.form['grade']
        info = request.form['info']

        cur = mysql.connection.cursor()

        cur.execute("UPDATE articles SET title=%s, profile = %s, skills = %s, grade = %s, info = %s WHERE id = %s", (title, profile, skills, grade, info, id))
        mysql.connection.commit()

        cur.close()

        flash('Internship Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form = form)

@app.route('/delete_article/<string:id>', methods= ['POST'])
@is_logged_in
def delete_article(id):
    cur = mysql.connection.cursor()
    
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article= cur.fetchone()

    if(article['company'].lower() != session['name'].lower() and article['company'].lower() != session['username'].lower()):
        flash('Invalid Delete Request', 'danger')
        return redirect(url_for('dashboard'))

    cur.execute("DELETE FROM articles WHERE id = %s", [id])
    mysql.connection.commit()
    cur.close()
    flash('Internship Post Deleted', 'success')

    return redirect(url_for('dashboard'))


class TicketForm(Form):
    name = StringField('Name of Buyer', [validators.Length(min=1, max=200)])
    email = StringField('Email Id', [validators.Length(min=1, max=200)])
    mobile = StringField('Mobile No.', [validators.Length(min=1, max=200)])
    paid = StringField('Amount Paid', [validators.Length(min=1, max=500)])
    balance = StringField('Amount Left to Pay', [validators.Length(min=1, max=200)])

@app.route('/add_ticket', methods = ['GET', 'POST'])
@is_logged_in
def add_ticket():
    form = TicketForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        mobile = form.mobile.data
        paid = form.paid.data
        balance = form.balance.data
        

        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO ticket(name, email, mobile, paid, balance, seller) VALUES(%s, %s, %s, %s, %s, %s)",(name, email, mobile, paid, balance, session['name']))

        mysql.connection.commit()

        id = cur.lastrowid

        flash('Ticket Added to database successfully at id : ' + str(id), 'success')

        return redirect(url_for('add_ticket'))
        
        cur.close()

    return render_template('add_ticket.html', form = form, seller = session['name'])

class TicketSearchForm(Form):

    choices = [('name', 'Name of Buyer'),

               ('seller', 'Ticket Seller'),

               ('mobile', 'Mobile of Buyer'),

               ('id', 'Ticket Id')]

    select = SelectField('Search for Tickets By:', choices=choices)

    search = StringField('Search Text:')

@app.route('/search', methods=['GET', 'POST'])
def search():

    search = TicketSearchForm(request.form)
    if request.method == 'POST':
        return search_results(search)
    return render_template('search.html', form=search)

@app.route('/results')
def search_results(search):
    results = []
    search_string = search.data['search']
    cur = mysql.connection.cursor()
    if search.data['search'] == '':
        result = cur.execute("SELECT * FROM ticket order by id;")
    else:
        if search.data['select'] == 'name':
            result = cur.execute("SELECT * FROM ticket where name = %s order by id;", [search_string])
        elif search.data['select'] == 'seller':
            result = cur.execute("SELECT * FROM ticket where seller = %s order by id;", [search_string])
        elif search.data['select'] == 'id':
            result = cur.execute("SELECT * FROM ticket where id = %s order by id;", [search_string])
        elif search.data['select'] == 'mobile':
            result = cur.execute("SELECT * FROM ticket where mobile = %s order by id;", [search_string])
    articles= cur.fetchall()
    if result == 0:
        flash('No results found!', 'danger')
        return redirect('/search')
    cur.close()
    return render_template('viewtickets.html', articles=articles)

@app.route('/viewtickets')
def viewtickets():
    cur = mysql.connection.cursor()
    if session['isadmin'] != 1:
        flash('Invalid Access!', 'danger')
        return redirect('/login')

    result = cur.execute("SELECT * FROM ticket order by id;")
    articles= cur.fetchall()
    return render_template('viewtickets.html', articles = articles)
    cur.close()

if(__name__ == '__main__'):
    app.run(threaded = True , debug = True)
