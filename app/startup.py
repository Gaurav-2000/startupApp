from flask import Flask, request, render_template, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import TextField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required

app = Flask(__name__)

app.config['SECRET_KEY'] = '698eab4f-35b4-4d55-9cb8-109b49b703dd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)

class LoginForm(FlaskForm):
    email_id = TextField("Email Address : ", [DataRequired()])
    password = PasswordField("Password : ", [DataRequired()])
    remember = BooleanField("Keep me signed in")
    submit = SubmitField("Login")

class SignupForm(FlaskForm):
    name = TextField("Name", [DataRequired()])
    email_id = TextField("Email Address : ", [DataRequired()])
    password = PasswordField("Password : ", [DataRequired()])
    confirm_password = PasswordField("Confirm Password : ", [DataRequired()])
    submit = SubmitField("Signup")

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#Database
class Users(UserMixin, db.Model):
    __tablename__='users'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    hashed_password = db.Column(db.String, nullable=False)
    email_id = db.Column(db.String, nullable=False)

    def get_id(self):
        return self.user_id

@app.route('/')
def index():
    return 'hello world'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('homepage'))
    form = LoginForm()
    if form.validate_on_submit():   
        email = form.email_id.data
        passwd = form.password.data
        user = Users.query.filter_by(email_id=email).first()
        if user.hashed_password == passwd:
            login_user(user, remember=form.remember.data)
            print("Logged in")
            
        else:
            print("Login Failed")
    return render_template('login.html', form=form)

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    form = SignupForm()
    if form.validate_on_submit():
        user_name = form.name.data
        email = form.email_id.data
        password = form.password.data
        user = Users(name=user_name, email_id=email, hashed_password=password)
        try:
            db.session.add(user)
            db.session.commit()
        except:
            print("Error")
            db.session.rollback()
    return render_template('registration.html', form=form)


@app.route('/logout')
@login_required
def logout():
    print("Logged out")
    logout_user()
    return redirect(url_for('login'))

@app.route('/homepage')
def homepage():
    return render_template('homepage.html')

@app.route('/loan')
def loan():
    return render_template('loan.html')

@app.route('/employees')
def employees():
    return render_template('employees.html') 

@app.route('/solution')
def solution():
    return render_template('solution.html') 

@app.route('/investors')
def investors():
    return render_template('investors.html')

@app.route('/locality')
def locality():
    return render_template('locality.html')

@app.route('/marketing')
def marketing():
    return render_template('marketing.html')

@app.route('/expert')
def expert():
    return render_template('expert.html')

@app.route('/office')
def office():
    return render_template('office.html')
if __name__=='__main__':
    app.run(debug=True)