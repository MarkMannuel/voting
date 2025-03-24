import dbm
from flask import Flask, render_template, request, redirect, url_for, g, session, flash,abort
import os
from werkzeug.utils import secure_filename
import sqlite3
from flask_bcrypt import Bcrypt
from flask_mail import Mail,Message

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['DATABASE'] = 'voting_system.db'
app.config['SECRET_KEY'] = '9793'
app.config['DEBUG'] = True
app.config['MAIL_SERVER']='smtp.example.com'
app.config['MAIL_PORT']=465
app.config['MAIL_USE_SSL']=True
app.config['MAIL_USERNAME']='omako9793@gmail.com'
app.config['MAIL_PASSWORD']='mark@100'


bcrypt = Bcrypt(app)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

mail=Mail(app)
def generate_reset_token():
    return 'some_random_token'

@app.route('/forgot_password', methods=['GET','POST'])
def forgot_password():
    if request.method=='POST':
        email=request.form['email']
        db=get_db()
        user=db.execute('SELECT * FROM voters WHERE email=?',(email,)).fetchone()
        if user:
            reset_token=generate_reset_token()
            db.execute('UPDATE voters SET reset_token=? WHERE email=?',(reset_token,email))
            db.commit()
            msg=Message('password Reset Request ',sender='omako@9793.com',recipients=[email])
            reset_link=url_for('reset_password',token=reset_token,_external=True)
            msg.body=f'Click the following link to reset your password:{reset_link}'
            mail.send(msg)
            flash('An email with instructions to reset your password has been sent to your email address.',
                  'success')
            return redirect(url_for('voter_login'))
        else:
            flash('No user found with that email address.','error')
            return render_template('forgot_password.html')
        

    return render_template('forgot_password.html')
         
@app.route('/reset_password/<token>',methods=['GET','POST'])
def reset_password(token):
    if request.method=='POST':
        new_password=request.form['new_password']
        confirm_password=request.form['confirm_password']
        if new_password!=confirm_password:
            flash('password do not match.','error')
        else:
            db=get_db()
            user=db.execute('SELECT * FROM voters WHERE reset_token=?',(token,)).fetchone()
            if user:
                hashed_password=bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.execute('UPDATE voters SET password=?,reset_token=NULL WHERE id=?',
                           (hashed_password,user['id']))
                db.commit()
                flash('Your password has been reset successfully. YOU can now log in with your new password','success')
                return redirect(url_for('voter_login'))
            else:
                flash('Invalid or expired reset token.','error')
                return render_template('reset_password.html',token=token)

@app.errorhandler(401)
def unapproved_voter_error(error):
    flash('your registration is pending approval by admin . you cannot vote untill approved','error')
    return redirect(url_for('index'))

@app.route('/register_voter', methods=['GET', 'POST'])
def register_voter():
    if request.method == 'POST':
        db = get_db() 
        email=request.form['email']
        reg_number= request.form['reg_number']
        password = request.form['password']
        confirm_password=request.form['confirm_password']
        existing_voter=db.execute("SELECT id FROM voters WHERE reg_number=?",(reg_number,)).fetchone()
        if existing_voter:
            return render_template('register_voter.html',error='Registration number already exists')
   
        if password!=confirm_password:
            return render_template('register_voter.html',error='passwords do not match')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        db.execute('''INSERT INTO voters (email,reg_number,password,approved)
                   VALUES(?,?,?,?)''',(email,reg_number,hashed_password,False))
        db.commit()

        Message='Registration Form has been submitted successfully,pending approval from the admin,success!.You can now login using the Link below'
        return render_template('register_voter.html',Message=Message)
    
    return render_template('register_voter.html')
    

@app.route('/voter_login', methods=['GET', 'POST'])
def voter_login():
    if request.method == 'POST':
        db = get_db()
        reg_number= request.form['reg_number']
        password = request.form['password']

        user = db.execute('''SELECT * FROM voters WHERE reg_number = ?''', (reg_number,)).fetchone()

        if user and bcrypt.check_password_hash(user['password'], password):
            session['voter_id'] = user['id']
            candidates=db.execute('''SELECT * FROM candidates''').fetchall()
            return render_template('voter_login.html',candidates=candidates,logged_in=True)
        else:
            error='Invalid reg_number or password!'
            return render_template('voter_login.html',error=error)

    return render_template('voter_login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username=='mark' and password=='mark@100':
            session['admin_logged_in']=True
            return redirect(url_for('admin_dashboard'))
        else:
            error='Invalid username or password'
            return render_template('admin_login.html',error=error)

    return render_template('admin_login.html')
 
   
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_logged_in' in session:
        db = get_db()
        pending_voters = db.execute('''SELECT * FROM voters WHERE approved = 0''').fetchall()
        return render_template('admin_dashboard.html', pending_voters=pending_voters)
    else:
        flash('You need to log in as admin.', 'error')
        return redirect(url_for('admin_login'))

@app.route('/approve_registration/<int:voter_id>')
def approve_registration(voter_id):
    if 'admin_logged_in' in session:
        db = get_db()
        db.execute('''UPDATE voters SET approved = 1 WHERE id = ?''', (voter_id,))
        db.commit()
        flash('Voter registration approved.', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        flash('You need to log in as admin.', 'error')
        return redirect(url_for('admin_login'))

@app.route('/register_candidate', methods=['GET', 'POST'])
def register_candidate():
    if request.method == 'POST':
        db = get_db()
        name = request.form['name']
    
      

        if not name :
            flash('Invalid input.', 'error')
            return render_template('register_candidate.html', error="Invalid input.")



        db.execute('''INSERT INTO candidates (name) VALUES (?)''', (name,))
        db.commit()
        flash('Candidate registration successful.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('register_candidate.html')

@app.route('/vote',methods=['GET','POST'])
def vote():
    if 'voter_id' not in session:
        return redirect(url_for('voter_login'))
    db=get_db()
    voter_id=session['voter_id']
    voter=db.execute('''SELECT * FROM voters WHERE id=?''',(voter_id,)).fetchone()

    if not voter['approved']:
      abort(401)

    has_voted=db.execute('''SELECT COUNT(*) FROM votes WHERE voter_id=?''',(voter_id,)).fetchone()[0]>0
    if request.method=='POST':
        candidate_id=request.form.get('candidate')

        if candidate_id:
            if has_voted:
                flash('you have already casted your vote','error')
            else:
                db.execute('''INSERT INTO votes (voter_id,candidate_id) VALUES (?,?)''',(voter_id,candidate_id))
                db.commit()
                flash('your vote has been casted successfully','success')
            return redirect(url_for('vote'))
              
        else:
            candidates=db.execute('''SELECT * FROM candidates''').fetchall()
            return render_template('vote.html',candidates=candidates,voter=voter,voted=has_voted,error='please select a candidate to vote')
    candidates=db.execute('''SELECT * FROM candidates''').fetchall()
    return render_template('vote.html',candidates=candidates,voter=voter,voted=has_voted)
 
@app.route('/votes_count')
def votes_count():
    if 'admin_logged_in' in session:
        db = get_db()
        candidates = db.execute('''SELECT id, name FROM candidates''').fetchall()
        votes_count = {}
        for candidate in candidates:
            candidate_id = candidate['id']
            count = db.execute('''SELECT COUNT(*) as count FROM votes WHERE candidate_id = ?''', (candidate_id,)).fetchone()['count']
            votes_count[candidate['name']] = count
        return render_template('votes_count.html', votes_count=votes_count)
    else:
        flash('You need to log in as admin.', 'error')
        return redirect(url_for('admin_login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))
if __name__=="__main__":
    app.run(debug=True)
