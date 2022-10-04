from flask import Flask, request, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import Email, DataRequired


app = Flask(__name__)
app.config['SECRET_KEY'] = 'any secret string'

Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///to_do.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    posts = relationship('ToDoList', back_populates='user')


class ToDoList(db.Model):
    __tablename__ = 'to_do_list'
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship('User', back_populates='posts')

    to_do = db.Column(db.String(250), nullable=False)
    did = db.Column(db.Integer, nullable=False)


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[Email(), DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    register = SubmitField('Register')


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[Email(), DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    login = SubmitField('LogIn')


class ToDo(FlaskForm):
    to_do = StringField('What you want to do?', validators=[DataRequired()])
    add = SubmitField('Add')
    logout = SubmitField('Logout')


@app.route('/', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('todolist'))
            else:
                flash("Password incorrect, please try again.")
                return redirect(url_for('login'))
        else:
            flash('That email does not exist, please try again.')
            return redirect(url_for('login'))

    return render_template('index.html', form=form)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already singed up with this email, log in instead!")
            return redirect(url_for('login'))

        has_and_salted_password = generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )

        user = User()
        user.name = form.name.data
        user.email = form.email.data
        user.password = has_and_salted_password

        db.session.add(user)
        db.session.commit()
        login_user(user)

        return redirect(url_for('todolist'))

    return render_template('register.html', form=form)


@app.route('/todolist', methods=["GET", "POST"])
@login_required
def todolist():
    form = ToDo()
    to_do = ToDoList.query.filter_by(user_id=current_user.id).all()

    if request.form.get('add'):
        lists = ToDoList()
        lists.user = current_user
        lists.user_id = current_user.id
        lists.to_do = form.to_do.data
        lists.did = 0

        db.session.add(lists)
        db.session.commit()
        return redirect(url_for('todolist'))
    elif request.form.get('logout'):
        logout_user()
        return redirect(url_for('login'))

    return render_template('to_do.html', form=form,  to_do=to_do)


@app.route('/delete/<int:todo_id>', methods=['GET', 'DELETE'])
@login_required
def delete(todo_id):
    todo_to_delete = ToDoList.query.get(todo_id)
    db.session.delete(todo_to_delete)
    db.session.commit()
    return redirect(url_for('todolist'))


@app.route('/replace/<int:todo_id>', methods=['GET', 'POST'])
@login_required
def replace(todo_id):
    to_change = ToDoList.query.get(todo_id)
    if to_change.did == 1:
        to_change.did = 0
        db.session.commit()
    else:
        to_change.did = 1
        db.session.commit()
    return redirect(url_for('todolist'))


if __name__ == "__main__":
    app.run()
