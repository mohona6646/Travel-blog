import csv, smtplib
from flask_bcrypt import bcrypt, Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, UserMixin, LoginManager, current_user, login_required
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, Form
from sqlalchemy.testing import db
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, RadioField, SelectField, BooleanField
from wtforms.fields.html5 import EmailField
from wtforms.validators import InputRequired, DataRequired, Email, EqualTo, Length, Regexp, ValidationError
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from wtforms.widgets import ListWidget, CheckboxInput

app = Flask(__name__)

app.secret_key = 'allo'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lite.db?check_same_thread=False'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "assignment287@gmail.com"
app.config['MAIL_PASSWORD'] = "CoronaVirus19"
mail = Mail(app)
app.config['USE_SESSION_FOR_NEXT'] = True


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def repr(self):
        return f"User1('{self.username}','{self.email}')"

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


@app.route("/")
def base():
    prefix = '/static/'
    return render_template('base.html')


@app.route("/Thailand/")
def thailand():
    return render_template("Thailand.html")


@app.route("/Morocco/")
def morocco():
    return render_template("Morocco.html")


@app.route("/Japan/")
def japan():
    return render_template("Japan.html")


@app.route("/Travel/")
def travel():
    return render_template("travel.html")


class LoginForm(FlaskForm):
    email = EmailField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('login')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/signIn', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('base'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash("Login Successfully")
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('base'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('signIn.html', form=form, title='login')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have logged out successfully')
    return redirect("/")


@app.route("/Contacts/")
@login_required
def contact():
    return render_template("contacts.html")


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    Submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


@app.route("/reset_password_request", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent.Please follow the instruction to reset the password', 'info')
        return redirect(url_for('login'))
    return render_template('Reset_password.html', title='Reset Password', form=form)


def validate_password(self, field):
    with open('data/common_passwords.txt') as f:
        for line in f.readlines():
            if field.data == line.strip():
                raise ValidationError('Your password is too common.')


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20),
                                       Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                              'Usernames must start with a letter and must have only letters, '
                                              'numbers, dots or underscores')])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(),
                                         Regexp("^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$",
                                                0,
                                                'Minimum eight characters, at least one uppercase letter, '
                                                'one lowercase letter and one number')])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*["
                                                                            "@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
                                                                            0,
                                                                            'Minimum eight characters, at least one '
                                                                            'uppercase letter, '
                                                                            'one lowercase letter, one number and one '
                                                                            'special character')])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


def send_reset_email(user1):
    token = user1.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user1.email])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_token', token=token, _external=True)}
    '''
    mail.send(msg)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


class MultiCheckboxField(SelectMultipleField):
    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()


class ReviewForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()], )
    comment = StringField("Review", validators=[InputRequired()])
    select = SelectField("Which country would you like to rate?", validators=[InputRequired()],
                         choices=[('C', 'Country'), ('T', 'Thailand'), ('M', 'Morocco'),
                                  ('J', 'Japan')])
    check = MultiCheckboxField("Which content did you like the most?", validators=[InputRequired()],
                               choices=[('H', 'History'), ('C', 'Culture'),
                                        ('F', 'Food')])
    radio = RadioField("What would be the overall rating for the page?", validators=[InputRequired()],
                       choices=[('1', '1'), ('2', '2'),
                                ('3', '3'), ('4', '4'), ('5', '5'),
                                ('6', '6'), ('7', '7'), ('8', '8'),
                                ('9', '9'), ('10', '10')])
    Submit = SubmitField("Submit")


@app.route('/review', methods=['GET', 'POST'])
def examples2():
    form = ReviewForm()
    if form.validate_on_submit():
        with open('data/submit.csv', 'a') as f:
            writer = csv.writer(f)
            writer.writerow([form.username.data, form.comment.data, form.select.data, form.radio.data])
            flash('Done! Thank you so much for your review!')
            return redirect(url_for('examples2'))
    return render_template('review.html', form=form)


@app.route("/reset_password_request/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)



if __name__ == '__main__':
    app.jinja_env.auto_reload = True
    app.run(debug=True)
