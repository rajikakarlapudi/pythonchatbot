from flask import Flask, render_template, request, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from passlib.hash import bcrypt
import nltk
from nltk.corpus import stopwords
import gunicorn

gunicorn.main()

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = 'hvgt5*&mdidindn$/bhsgssdbj:+//htw'  # Replace with a strong secret key

# User class with password hashing
class User(UserMixin):
    def __init__(self, username, password):
        self.id = username
        self.password = bcrypt.hash(password)

users = {}  # Dictionary to store usernames and hashed passwords

# Authentication routes (login, register, etc.)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Input validation
        if username in users:
            return render_template('PYTHONCHATBOT/register.html', message='Username already exists.')
        if len(password) < 8:
            return render_template('PYTHONCHATBOT/register.html', message='Password must be at least 8 characters long.')
        if not ('@' in email and '.' in email):
            return render_template('PYTHONCHATBOT/register.html', message='Invalid email format.')

        # Hash password before storing
        hashed_password = bcrypt.hash(password)
        users[username] = User(username, hashed_password)
        return render_template('PYTHONCHATBOT/login.html', message='Registration successful!')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username not in users:
            return render_template('PYTHONCHATBOT/login.html', message='Username not found.')

        user = users[username]
        if not bcrypt.verify(password, user.password):
            return render_template('PYTHONCHATBOT/login.html', message='Invalid password.')

        login_user(user)
        return render_template('PYTHONCHATBOT/chat.html', username=username)
    return render_template('PYTHONCHATBOT/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('PYTHONCHATBOT/login.html', message='Logged out successfully!')

# Chat route handling user messages
@app.route('/chat', methods=['POST'])
@login_required
def chat():
    message = request.form.get('message')
    username = session['username']

    # Basic NLP pre-processing
    processed_text = preprocess(message)
    intent = identify_intent(processed_text)

    # Generate response based on intent (expand with more intents and responses)
    response = get_response(intent)

    return render_template('PYTHONCHATBOT/chat.html', username=username, message=message, response=response)

# Helper functions for NLP tasks and response generation
def preprocess(text):
    tokens = nltk.word_tokenize(text)
    stop_words = stopwords.words('english')
    filtered_tokens = [word for word in tokens if word not in stop_words]
    return filtered_tokens.lower()  # Convert to lowercase

def identify_intent(processed_text):
    # Implement logic to identify user intent based on keywords or pre-trained models
    # (e.g., greetings, questions about specific topics)
    if any(word in processed_text for word in ['hello', 'hi', 'hey']):
        return 'greeting'
    elif any(word in processed_text for word in ['weather', 'forecast']):
        return 'weather'
    else:
        return 'default'  # Default fallback intent

def get_response(intent):
    # Define pre-programmed responses based on intent
    responses = {
        'greeting': f"Hi {session['username']}! How can I help you today?",
        'weather': "Sorry, I can't provide weather information yet. But I'm learning!",
        'default': "I'm still under development, but I'm learning to"
    }

app.run(debug=True,port=4040)
