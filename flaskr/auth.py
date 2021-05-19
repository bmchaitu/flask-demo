import functools
from flask import Blueprint, redirect, render_template, request, session, url_for, flash, g
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register',methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        if not username:
            error = 'Username not Defined'
        elif not password:
            error = "Password is not given"
        elif db.execute(
            'SELECT id FROM user WHERE username == ?', (username,)
        ).fetchone() is not None:
            error = f"user is already registered"
        
        if error is None:
            db.execute(
                'INSERT INTO user (username,password) VALUES(?,?)', (username,generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))
        
        flash(error)
    return render_template('auth/register.html')


@bp.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        db=get_db()
        error = None
        if not username:
            error = "Username is required"
        elif not password:
            error = "Password is required"
        user = db.execute('SELECT * from user WHERE username = ? ',(username,)).fetchone()
        if not user:
            error = "User not exists"
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('blog.index'))
        flash(error)
    return render_template('auth/login.html')

@bp.before_app_request
def check_loggedIn():
    db = get_db()
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = db.execute(
            'SELECT * from user WHERE id = ?',(user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('blog.index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


