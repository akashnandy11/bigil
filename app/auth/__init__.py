from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db, bcrypt
from app.models import User, AuditLog
from datetime import datetime

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            
            log = AuditLog(
                user_id=user.id,
                action='LOGIN',
                resource_type='auth',
                ip_address=request.remote_addr,
                details=f'Successful login from {request.remote_addr}',
                status='success'
            )
            db.session.add(log)
            db.session.commit()
            
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.full_name or user.username}!', 'success')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            flash('Invalid credentials. Access denied.', 'danger')
            
    return render_template('auth/login.html')


@auth.route('/logout')
@login_required
def logout():
    log = AuditLog(
        user_id=current_user.id,
        action='LOGOUT',
        resource_type='auth',
        ip_address=request.remote_addr,
        details='User logged out',
        status='success'
    )
    db.session.add(log)
    db.session.commit()
    logout_user()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('auth.login'))
