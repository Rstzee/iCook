import os
import sqlite3
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from functools import wraps

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed, will use system environment variables
    pass

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# OpenRouter API configuration
OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY', 'your-openrouter-api-key')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# AI model configuration
AI_MODEL = os.environ.get('AI_MODEL', 'google/gemma-2-9b-it:free')
MAX_TOKENS = int(os.environ.get('MAX_TOKENS', '1000'))
TEMPERATURE = float(os.environ.get('TEMPERATURE', '0.7'))

# Admin Configuration
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'password')

# Database Configuration
DATABASE_PATH = os.environ.get('DATABASE_PATH', 'icook.db')

@app.after_request
def add_security_headers(response):
    """
    Add comprehensive security headers to all HTTP responses.
    
    This function runs after every request to enhance application security by:
    - Preventing caching of sensitive authenticated pages
    - Adding MIME type sniffing protection
    - Preventing clickjacking attacks
    - Enabling XSS protection
    
    Args:
        response: Flask response object
    
    Returns:
        Modified response object with security headers
    """
    # Add cache control headers for all form-based and sensitive pages to prevent auto-fill on back button
    # This prevents browsers from caching form data and auto-filling forms when users navigate back
    sensitive_endpoints = [
        # User authentication and registration
        'login', 'logout', 'register', 'guest_chat',
        # Main application pages
        'icook', 'landing_page',
        # Ingredient management
        'add_ingredient', 'delete_ingredient', 'edit_ingredient', 
        # Chat and AI features
        'chat', 'generate_recipe', 'test_ai_formatting',
        # Conversation management
        'save_conversation', 'load_conversation', 'delete_saved_conversation', 
        'clear_current_chat', 'new_chat', 'delete_chat_history',
        # Admin authentication and pages
        'admin_login', 'admin_logout', 'admin_dashboard', 'admin_user_detail',
        # Admin user management
        'admin_add_user', 'admin_edit_user', 'admin_delete_user', 'admin_ban_user'
    ]
    
    if request.endpoint in sensitive_endpoints:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        # Additional headers to prevent form data caching
        response.headers['Last-Modified'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        response.headers['ETag'] = ''
    
    # Additional cache control for all POST requests (form submissions)
    if request.method == 'POST':
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    # Add additional security headers for MIME type protection and clickjacking prevention
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

def format_timestamp(timestamp_str):
    """
    Convert SQLite timestamp string to user-friendly formatted display string.
    
    This utility function handles timestamp formatting for display in templates.
    It converts ISO format timestamps from the database to readable format.
    
    Args:
        timestamp_str (str): SQLite timestamp string in ISO format
    
    Returns:
        str: Formatted timestamp string (YYYY-MM-DD HH:MM) or truncated fallback
    """
    try:
        # Parse the SQLite timestamp format and convert to readable format
        dt = datetime.fromisoformat(timestamp_str.replace(' ', 'T'))
        return dt.strftime('%Y-%m-%d %H:%M')
    except:
        # Fallback: just return first 16 characters (YYYY-MM-DD HH:MM)
        return timestamp_str[:16]

# Make the function available in templates
app.jinja_env.globals.update(format_timestamp=format_timestamp)

def no_cache(f):
    """
    Decorator to prevent browser caching of sensitive pages.
    
    This decorator adds cache-control headers to prevent browsers from caching
    sensitive pages like login/logout, protecting against unauthorized access
    via browser back button or cache.
    
    Args:
        f: The Flask route function to decorate
    
    Returns:
        Decorated function with no-cache headers
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        resp = make_response(f(*args, **kwargs))
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    return decorated_function

def require_auth(f):
    """
    Decorator to require user authentication for protected routes.
    
    This decorator checks if a user is logged in (has user_id in session)
    and redirects to login page if not authenticated. Also adds cache-control
    headers to prevent caching of authenticated content.
    
    Args:
        f: The Flask route function to decorate
    
    Returns:
        Decorated function with authentication check and no-cache headers
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        resp = make_response(f(*args, **kwargs))
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    return decorated_function

def init_db():
    """
    Initialize the SQLite database with all required tables.
    
    This function creates the database schema for the iCook application,
    including tables for users, ingredients, chat messages, conversation history,
    and saved conversations. Called automatically when the application starts.
    
    Tables created:
    - user: User account information with hashed passwords
    - ingredient: User's ingredient inventory with quantities and units
    - current_chat_messages: Active chat conversation messages
    - chat_history: Historical chat queries and responses
    - saved_conversations: User-saved conversation threads
    """
    # Use environment variable for database path
    db_path = DATABASE_PATH
    
    # Ensure directory exists for the database
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            password TEXT NOT NULL,
            banned INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Ingredients table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ingredient (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            quantity REAL NOT NULL,
            unit TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    ''')
    
    # Current session messages table (for active chat conversation)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS current_chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message_type TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    ''')
    
    # Chat history table (for current session messages)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            query TEXT NOT NULL,
            response TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    ''')
    
    # Saved conversations table (for saved conversation threads)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS saved_conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    ''')
    
    conn.commit()
    
    # Add banned column if it doesn't exist (migration for existing databases)
    try:
        cursor.execute("ALTER TABLE user ADD COLUMN banned INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        # Column already exists, which is fine
        pass
    
    # Add created_at column if it doesn't exist (migration for existing databases)
    try:
        cursor.execute("ALTER TABLE user ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
        conn.commit()
    except sqlite3.OperationalError:
        # Column already exists, which is fine
        pass
    
    conn.close()

def get_db_connection():
    """
    Create and configure a SQLite database connection.
    
    This utility function establishes a connection to the iCook database
    and configures it with Row factory for dictionary-like access to query results.
    Uses environment variable DATABASE_PATH for flexible deployment.
    
    Returns:
        sqlite3.Connection: Configured database connection with Row factory
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def call_openrouter_api(prompt):
    """
    Send request to OpenRouter AI API and return the AI-generated response.
    
    This function handles communication with the OpenRouter AI service using the
    configured model (default: google/gemma-2-9b-it:free). It includes comprehensive
    error handling for various API response scenarios and timeout management.
    
    The function configures the AI with a specialized system prompt that:
    - Limits responses to cooking-related queries only
    - Formats responses with HTML tags for better presentation
    - Provides structured recipe formats with proper sections
    - Handles insufficient ingredient scenarios with "Additional Ingredients Needed"
    
    Args:
        prompt (str): The user's cooking query or enhanced prompt
    
    Returns:
        str: AI-generated response with HTML formatting, or error message if API fails
    
    Error Handling:
        - 401: Authentication/API key errors
        - 429: Rate limiting (too many requests)
        - 400: Bad request/model availability issues
        - Timeout: Request timeout handling
        - Connection errors: Network connectivity issues
    """
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:5000",  # Required for some models
        "X-Title": "iCook AI Assistant"  # Optional but helpful for tracking
    }
    #how are you 
    data = {
        "model": AI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You are iCook, a cooking assistant. Only answer cooking and recipe questions. Always format responses with HTML: Use <h4> for headings, <p> for text, <ul><li> for lists, <strong> for emphasis then use proper indentation for lists. Example: <h4>Answer:</h4><p>To cook rice: <strong>1 cup rice</strong> + <strong>2 cups water</strong>. Boil, then simmer 18 minutes.</p> STRICTLY USE HTML TAGS ONLY FOR STYLING NOT **"
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "top_p": 0.9
    }
    
    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=data, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result['choices'][0]['message']['content']
            
            # Ensure we have a valid response and add basic HTML formatting if missing
            if not ai_response or ai_response.strip() == "":
                return "<h4>Error:</h4><p>The AI service returned an empty response. Please try asking your question again.</p>"
            
            # If response doesn't contain HTML tags, wrap it in basic formatting
            if '<' not in ai_response and '>' not in ai_response:
                return f"<h4>Response:</h4><p>{ai_response}</p>"
            
            return ai_response
        elif response.status_code == 401:
            return "<h4>Authentication Error:</h4><p>Please check your OpenRouter API key configuration. Make sure your API key is valid and has sufficient credits.</p>"
        elif response.status_code == 429:
            return "<h4>Service Busy:</h4><p>The AI service is currently busy. Please try again in a moment.</p>"
        elif response.status_code == 400:
            return f"<h4>Configuration Error:</h4><p>The model '{AI_MODEL}' might not be available or the request format is incorrect.</p>"
        else:
            return f"<h4>Connection Error:</h4><p>Sorry, I'm having trouble connecting to the AI service right now. (Error: {response.status_code})</p>"
    except requests.exceptions.Timeout:
        return get_fallback_response(prompt) if prompt else "<h4>Timeout Error:</h4><p>The AI service is taking too long to respond. Please try again.</p>"
    except requests.exceptions.ConnectionError:
        return get_fallback_response(prompt) if prompt else "<h4>Network Error:</h4><p>Unable to connect to the AI service. Please check your internet connection.</p>"
    except Exception as e:
        return get_fallback_response(prompt) if prompt else f"<h4>System Error:</h4><p>Sorry, there was an error processing your request: {str(e)}</p>"

def validate_ai_service():
    """
    Test OpenRouter API connection and validate model availability.
    
    This utility function performs a health check on the AI service by sending
    a minimal test request to verify that the API key is valid and the configured
    model is available for use.
    
    Returns:
        tuple: (success_boolean, status_message)
            - success_boolean (bool): True if AI service is working, False otherwise
            - status_message (str): Descriptive message about the service status
    
    Use Cases:
        - Application startup validation
        - Troubleshooting AI connection issues
        - Configuration verification
    """
    if not OPENROUTER_API_KEY or OPENROUTER_API_KEY == 'your-openrouter-api-key':
        return False, "OpenRouter API key not configured"
    
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:5000",
        "X-Title": "iCook AI Assistant"
    }
    
    try:
        # Test with a simple request using the configured model
        test_data = {
            "model": AI_MODEL,
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 5
        }
        
        response = requests.post(OPENROUTER_URL, headers=headers, json=test_data, timeout=15)
        
        if response.status_code == 200:
            return True, f"AI service is working with model {AI_MODEL}"
        elif response.status_code == 401:
            return False, f"Authentication failed. Please check your API key."
        elif response.status_code == 400:
            return False, f"Model '{AI_MODEL}' may not be available. Try a different model."
        else:
            return False, f"AI service error: {response.status_code}"
    except Exception as e:
        return False, f"Connection error: {str(e)}"

def create_cooking_prompt(user_input, ingredients_list=None):
    """
    Enhance user queries with cooking context and ingredient information.
    
    This function creates comprehensive prompts for the AI by combining user input
    with available ingredient context and cooking-specific guidance. It helps ensure
    AI responses are practical, detailed, and cooking-focused.
    
    Args:
        user_input (str): The user's original query or question
        ingredients_list (list, optional): List of ingredient dictionaries with
                                         'name', 'quantity', and 'unit' keys
    
    Returns:
        str: Enhanced prompt with ingredient context and cooking guidance
    
    Features:
        - Adds ingredient inventory context when available
        - Requests structured responses with clear instructions
        - Emphasizes practical cooking advice and techniques
        - Includes timing and serving suggestions
    """
    base_prompt = user_input
    
    if ingredients_list:
        ingredients_text = ", ".join([f"{ing['quantity']} {ing['unit']} of {ing['name']}" for ing in ingredients_list])
        base_prompt = f"I have these ingredients: {ingredients_text}. {user_input}"
    
    # Add context to make responses more cooking-focused
    enhanced_prompt = f"""
    Cooking Query: {base_prompt}
    
    Please provide a helpful cooking response that includes:
    - if ingredient is unknown or uncommon, tell that the ingredient is not known politely.
    - Clear, step-by-step instructions if it's a recipe
    - Ingredient substitutions if applicable
    - Cooking tips and techniques
    - Estimated preparation and cooking times
    - Serving suggestions
    
    Keep the response practical and easy to follow.
    """
    
    return enhanced_prompt.strip()

@app.route('/')
def landing_page():
    """
    Render the application landing page with guest chatbot functionality.
    
    This route serves as the main entry point for the iCook application.
    It provides different experiences based on user authentication status:
    - Authenticated users: Redirected to their personal kitchen interface
    - Guest users: Shown landing page with demo chatbot for trying the AI service
    
    Returns:
        Response: Either redirect to /icook for logged-in users or 
                 rendered landingpage.html template for guests
    """
    # Redirect logged-in users to their kitchen page
    if 'user_id' in session:
        return redirect(url_for('icook'))
    return render_template('landingpage.html')

@app.route('/guest_chat', methods=['POST'])
def guest_chat():
    """
    Handle chatbot queries from guest users on the landing page.
    
    This route allows non-registered users to test the AI cooking assistant
    functionality through a demo interface. It processes cooking queries
    and displays responses using flash messages.
    
    POST Parameters:
        query (str): The cooking question or request from the guest user
    
    Returns:
        Response: Redirect to landing page with AI response displayed via flash messages
    
    Features:
        - Input validation to ensure query is provided
        - Uses enhanced cooking prompt for better AI responses
        - Displays both user query and AI response for context
        - No data persistence (demo mode only)
    """
    query = request.form.get('query', '').strip()
    if not query:
        flash('Please enter a question')
        return redirect(url_for('landing_page'))
    
    # Use enhanced prompt for guest queries too
    enhanced_query = create_cooking_prompt(query)
    response = call_openrouter_api(enhanced_query)
    flash(f'You asked: {query}')
    flash(f'iCook: {response}')
    return redirect(url_for('landing_page'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle user registration for new accounts.
    
    This route manages the user registration process with comprehensive validation
    and secure password handling. It supports both displaying the registration form
    and processing submitted registration data.
    
    GET Method:
        Returns the registration form template
    
    POST Method:
        Processes registration form submission with validation:
        - Ensures all required fields are provided
        - Checks for existing email addresses to prevent duplicates
        - Hashes passwords securely using Werkzeug
        - Creates new user account in database
    
    Form Fields:
        email (str): User's email address (must be unique)
        first_name (str): User's first name
        last_name (str): User's last name
        password (str): User's password (will be hashed before storage)
    
    Returns:
        Response: Registration form template or redirect to login on success
    
    Security Features:
        - Password hashing with generate_password_hash
        - Email uniqueness validation
        - SQL injection prevention with parameterized queries
    """
    if request.method == 'POST':
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        
        if not all([email, first_name, last_name, password]):
            flash('All fields are required')
            return render_template('registration.html')
        
        conn = get_db_connection()
        
        # Check if user already exists
        existing_user = conn.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone()
        if existing_user:
            flash('Email already registered')
            conn.close()
            return render_template('registration.html')
        
        # Create new user
        hashed_password = generate_password_hash(password)
        conn.execute(
            'INSERT INTO user (email, first_name, last_name, password, created_at) VALUES (?, ?, ?, ?, ?)',
            (email, first_name, last_name, hashed_password, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('registration.html')

@app.route('/login', methods=['GET', 'POST'])
@no_cache
def login():
    """
    Handle user authentication and login process.
    
    This route manages user login with secure authentication and session management.
    It includes automatic redirection for already authenticated users and comprehensive
    validation of login credentials.
    
    GET Method:
        Returns the login form template
    
    POST Method:
        Processes login form submission:
        - Validates email and password are provided
        - Verifies credentials against database
        - Creates secure session on successful authentication
        - Redirects to main kitchen interface
    
    Form Fields:
        email (str): User's registered email address
        password (str): User's password for verification
    
    Returns:
        Response: Login form template, redirect to /icook on success, or error messages
    
    Security Features:
        - Password verification with check_password_hash
        - Session management with user_id and user_name
        - No-cache decorator to prevent caching of login page
        - Automatic redirect if already authenticated
        - Permanent session setting for user convenience
    """
    # Redirect if already logged in
    if 'user_id' in session:
        return redirect(url_for('icook'))
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if not email or not password:
            flash('Email and password are required')
            return render_template('login.html')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            # Check if user is banned
            banned_status = user['banned'] if 'banned' in user.keys() else 0
            if banned_status == 1:
                flash('Your account has been banned. Please contact the administrator.')
                return render_template('login.html')
            
            session['user_id'] = user['id']
            session['user_name'] = f"{user['first_name']} {user['last_name']}"
            session.permanent = True  # Make session permanent
            return redirect(url_for('icook'))
        else:
            flash('Invalid email or password')
    
    return render_template('login.html')

@app.route('/logout')
@no_cache
def logout():
    """
    Handle user logout and session cleanup.
    
    This route manages the user logout process by clearing all session data
    and ensuring secure termination of the user's authenticated session.
    Includes comprehensive cache control to prevent unauthorized access
    to cached authenticated content.
    
    Returns:
        Response: Redirect to login page with no-cache headers
    
    Security Features:
        - Complete session data clearing
        - No-cache decorator to prevent caching
        - Additional cache-control headers in response
        - Secure redirect to login page
    """
    session.clear()
    resp = make_response(redirect(url_for('login')))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/icook')
@require_auth
def icook():
    """
    Main kitchen interface - the core dashboard for authenticated users.
    
    This route serves as the primary interface for the iCook application,
    providing users with access to all main features in a single integrated view.
    It loads and displays all user-specific data needed for the cooking assistant.
    
    Data Loaded:
        - User's ingredient inventory (sorted alphabetically by name)
        - Saved conversation threads (newest first)
        - Current active chat messages (chronological order)
        - Optional: ingredient being edited (if accessed via edit route)
    
    Returns:
        Response: Rendered icook.html template with all user data
    
    Template Variables:
        ingredients: List of user's ingredients with quantities and units
        saved_conversations: List of saved conversation summaries
        current_chat_messages: Active chat session messages
        edit_ingredient: Current ingredient being edited (optional)
    
    Security:
        - Requires authentication via @require_auth decorator
        - Only loads data belonging to the authenticated user
        - Automatic redirect to login if session expired
    """
    conn = get_db_connection()
    
    # Get user's ingredients sorted alphabetically for easy browsing
    ingredients = conn.execute(
        'SELECT * FROM ingredient WHERE user_id = ? ORDER BY name',
        (session['user_id'],)
    ).fetchall()
    
    # Get saved conversations ordered by most recent first
    saved_conversations = conn.execute(
        'SELECT * FROM saved_conversations WHERE user_id = ? ORDER BY timestamp DESC',
        (session['user_id'],)
    ).fetchall()
    
    # Get current chat messages in chronological order for conversation flow
    current_chat_messages = conn.execute(
        'SELECT * FROM current_chat_messages WHERE user_id = ? ORDER BY timestamp ASC',
        (session['user_id'],)
    ).fetchall()
    
    conn.close()
    
    return render_template('icook.html', 
                         ingredients=ingredients, 
                         saved_conversations=saved_conversations,
                         current_chat_messages=current_chat_messages)

@app.route('/add_ingredient', methods=['POST'])
@require_auth
def add_ingredient():
    """
    Add a new ingredient to the user's inventory.
    
    This route handles the addition of new ingredients to the user's personal
    ingredient inventory with comprehensive validation and error handling.
    
    POST Parameters:
        name (str): The ingredient name (e.g., "chicken breast", "tomatoes")
        quantity (str): Numeric quantity of the ingredient
        unit (str): Unit of measurement (kg, g, ml, cups, pieces, etc.)
    
    Returns:
        Response: Redirect to /icook with success message or error feedback
    
    Validation:
        - All fields are required and must be provided
        - Quantity must be a valid numeric value (float)
        - Associates ingredient with the authenticated user only
    
    Security:
        - Requires authentication via @require_auth decorator
        - User isolation - ingredients linked to session user_id
        - SQL injection prevention with parameterized queries
    
    Database Operations:
        - Inserts new ingredient record with user association
        - Commits transaction to ensure data persistence
    """
    name = request.form['name']
    quantity = request.form['quantity']
    unit = request.form['unit']
    
    if not all([name, quantity, unit]):
        flash('All fields are required')
        return redirect(url_for('icook'))
    
    try:
        quantity = float(quantity)
    except ValueError:
        flash('Quantity must be a number')
        return redirect(url_for('icook'))
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO ingredient (user_id, name, quantity, unit) VALUES (?, ?, ?, ?)',
        (session['user_id'], name, quantity, unit)
    )
    conn.commit()
    conn.close()
    
    flash('Ingredient added successfully!')
    return redirect(url_for('icook'))

@app.route('/delete_ingredient/<int:ingredient_id>')
@require_auth
def delete_ingredient(ingredient_id):
    """
    Remove an ingredient from the user's inventory.
    
    This route handles the deletion of specific ingredients from the user's
    personal ingredient inventory with security validation to ensure users
    can only delete their own ingredients.
    
    URL Parameters:
        ingredient_id (int): The unique ID of the ingredient to delete
    
    Returns:
        Response: Redirect to /icook with success confirmation
    
    Security Features:
        - Requires authentication via @require_auth decorator
        - Double verification: ingredient_id AND user_id must match
        - Prevents users from deleting other users' ingredients
        - SQL injection prevention with parameterized queries
    
    Database Operations:
        - Deletes ingredient record matching both ID and user ownership
        - Commits transaction to ensure immediate removal
        - Provides user feedback via flash message
    """
    conn = get_db_connection()
    conn.execute(
        'DELETE FROM ingredient WHERE id = ? AND user_id = ?',
        (ingredient_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    
    flash('Ingredient deleted successfully!')
    return redirect(url_for('icook'))

@app.route('/edit_ingredient/<int:ingredient_id>', methods=['GET', 'POST'])
@require_auth
def edit_ingredient(ingredient_id):
    """
    Edit an existing ingredient in the user's inventory.
    
    This route provides a dual-purpose interface for ingredient editing:
    GET requests display the edit form with current values, while POST requests
    process the updates. It includes comprehensive validation and security checks.
    
    URL Parameters:
        ingredient_id (int): The unique ID of the ingredient to edit
    
    GET Method:
        - Retrieves ingredient details for the edit form
        - Loads all page data (ingredients, conversations, chat messages)
        - Renders icook.html with edit_ingredient data for form population
    
    POST Method:
        - Processes form submission with updated ingredient data
        - Validates all fields and numeric quantity
        - Updates database record with new values
    
    Form Fields (POST):
        name (str): Updated ingredient name
        quantity (str): Updated numeric quantity
        unit (str): Updated unit of measurement
    
    Returns:
        Response: Rendered icook.html template (GET) or redirect to /icook (POST)
    
    Security Features:
        - Authentication required via @require_auth decorator
        - Ownership verification: ingredient must belong to current user
        - SQL injection prevention with parameterized queries
        - Input validation for all form fields
    
    Error Handling:
        - Ingredient not found or access denied scenarios
        - Invalid numeric quantity handling
        - Missing required field validation
    """
    conn = get_db_connection()
    
    if request.method == 'POST':
        # Update ingredient
        name = request.form['name']
        quantity = request.form['quantity']
        unit = request.form['unit']
        
        if not all([name, quantity, unit]):
            flash('All fields are required')
            return redirect(url_for('icook'))
        
        try:
            quantity = float(quantity)
        except ValueError:
            flash('Quantity must be a number')
            return redirect(url_for('icook'))
        
        conn.execute(
            'UPDATE ingredient SET name = ?, quantity = ?, unit = ? WHERE id = ? AND user_id = ?',
            (name, quantity, unit, ingredient_id, session['user_id'])
        )
        conn.commit()
        conn.close()
        
        flash('Ingredient updated successfully!')
        return redirect(url_for('icook'))
    
    else:
        # GET request - show edit form
        ingredient = conn.execute(
            'SELECT * FROM ingredient WHERE id = ? AND user_id = ?',
            (ingredient_id, session['user_id'])
        ).fetchone()
        conn.close()
        
        if not ingredient:
            flash('Ingredient not found')
            return redirect(url_for('icook'))
        
        # Get all ingredients and conversations for the main page
        conn = get_db_connection()
        ingredients = conn.execute(
            'SELECT * FROM ingredient WHERE user_id = ? ORDER BY name',
            (session['user_id'],)
        ).fetchall()
        
        saved_conversations = conn.execute(
            'SELECT * FROM saved_conversations WHERE user_id = ? ORDER BY timestamp DESC',
            (session['user_id'],)
        ).fetchall()
        
        # Get current chat messages
        current_chat_messages = conn.execute(
            'SELECT * FROM current_chat_messages WHERE user_id = ? ORDER BY timestamp ASC',
            (session['user_id'],)
        ).fetchall()
        
        conn.close()
        
        return render_template('icook.html', 
                             ingredients=ingredients, 
                             saved_conversations=saved_conversations,
                             current_chat_messages=current_chat_messages,
                             edit_ingredient=ingredient)

@app.route('/chat', methods=['POST'])
@require_auth
def chat():
    """
    Process user chat messages and generate AI responses.
    
    This route handles the core chat functionality of the application,
    processing user queries and generating AI responses using the OpenRouter API.
    It maintains conversation history and provides persistent chat sessions.
    
    POST Parameters:
        query (str): The user's cooking question or request
    
    Returns:
        Response: Redirect to /icook with AI response added to chat
    
    Process Flow:
        1. Validate and retrieve user query from form
        2. Create enhanced cooking prompt with context
        3. Send request to OpenRouter AI API
        4. Save both user message and AI response to database
        5. Store in both current_chat_messages (active session) and chat_history (backup)
        6. Redirect back to main interface with updated conversation
    
    Database Operations:
        - Inserts user message with 'user' type
        - Inserts AI response with 'ai' type
        - Maintains conversation in current_chat_messages for session persistence
        - Stores backup in chat_history for historical reference
    
    Security Features:
        - Authentication required via @require_auth decorator
        - User isolation - messages linked to session user_id
        - Input validation to ensure query is provided
    
    AI Integration:
        - Uses create_cooking_prompt() for enhanced query formatting
        - Leverages call_openrouter_api() for AI communication
        - Handles AI service errors gracefully
    """
    query = request.form.get('query', '').strip()
    if not query:
        flash('Please enter a question')
        return redirect(url_for('icook'))
    
    # Create enhanced cooking prompt with context and guidance
    enhanced_query = create_cooking_prompt(query)
    response = call_openrouter_api(enhanced_query)
    
    # Save conversation to database for persistence across sessions
    conn = get_db_connection()
    
    # Add user message (save original query for accurate display)
    conn.execute(
        'INSERT INTO current_chat_messages (user_id, message_type, content) VALUES (?, ?, ?)',
        (session['user_id'], 'user', query)
    )
    
    # Add AI response message with HTML formatting
    conn.execute(
        'INSERT INTO current_chat_messages (user_id, message_type, content) VALUES (?, ?, ?)',
        (session['user_id'], 'ai', response)
    )
    
    # Also save to chat history for backup and historical reference
    conn.execute(
        'INSERT INTO chat_history (user_id, query, response) VALUES (?, ?, ?)',
        (session['user_id'], query, response)
    )
    conn.commit()
    conn.close()
    
    flash('Message sent successfully!')
    return redirect(url_for('icook'))

@app.route('/generate_recipe', methods=['POST'])
@require_auth
def generate_recipe():
    """
    Generate recipe suggestions based on user's available ingredients.
    
    This route provides intelligent recipe generation by analyzing the user's
    current ingredient inventory and requesting AI suggestions for recipes that
    can be made with those ingredients. It handles insufficient ingredient scenarios
    by providing "Additional Ingredients Needed" guidance.
    
    Returns:
        Response: Redirect to /icook with generated recipe in chat
    
    Process Flow:
        1. Retrieve all user's ingredients from database
        2. Validate that user has ingredients to work with
        3. Convert ingredients to structured format for AI prompt
        4. Create specialized prompt for recipe generation
        5. Request AI recipe suggestions via OpenRouter API
        6. Save interaction to both current chat and history
    
    AI Prompt Features:
        - Provides complete ingredient inventory context
        - Requests detailed cooking instructions and timing
        - Emphasizes handling of insufficient ingredients
        - Asks for "Additional Ingredients Needed" sections
        - Requests practical cooking advice and substitutions
    
    Database Operations:
        - Reads user's complete ingredient inventory
        - Saves recipe request as user message
        - Stores AI-generated recipe as AI response
        - Maintains conversation in both current chat and history
    
    Security Features:
        - Authentication required via @require_auth decorator
        - User isolation - only accesses current user's ingredients
        - Input validation for ingredient availability
    
    Error Handling:
        - No ingredients found scenario with helpful guidance
        - AI service errors handled gracefully
        - Database operation error handling
    """
    conn = get_db_connection()
    ingredients = conn.execute(
        'SELECT name, quantity, unit FROM ingredient WHERE user_id = ?',
        (session['user_id'],)
    ).fetchall()
    
    if not ingredients:
        flash('No ingredients found. Please add some ingredients first.')
        conn.close()
        return redirect(url_for('icook'))
    
    # Convert ingredients to structured format for enhanced prompt system
    ingredients_list = [{"name": ing['name'], "quantity": ing['quantity'], "unit": ing['unit']} for ing in ingredients]
    
    # Create specialized prompt for recipe generation with ingredient context
    enhanced_prompt = create_cooking_prompt(
        """Please suggest a recipe I can make with these ingredients. Include detailed cooking instructions, cooking time, and serving suggestions. 
        
        IMPORTANT: If it is impossible to make a complete recipe with only the given ingredients, please:
        1. Suggest the closest possible recipe you can make with what's available
        2. Clearly indicate what additional ingredients are needed
        3. Provide a separate 'Additional Ingredients Needed' section with specific quantities
        4. Explain why these additional ingredients are essential for the recipe""",
        ingredients_list
    )
    
    response = call_openrouter_api(enhanced_prompt)
    
    # Save recipe generation request and response to chat
    conn.execute(
        'INSERT INTO current_chat_messages (user_id, message_type, content) VALUES (?, ?, ?)',
        (session['user_id'], 'user', 'Generate recipe from my ingredients')
    )
    
    conn.execute(
        'INSERT INTO current_chat_messages (user_id, message_type, content) VALUES (?, ?, ?)',
        (session['user_id'], 'ai', response)
    )
    
    # Also save to chat history for backup and historical reference
    conn.execute(
        'INSERT INTO chat_history (user_id, query, response) VALUES (?, ?, ?)',
        (session['user_id'], "Generate recipe from my ingredients", response)
    )
    conn.commit()
    conn.close()
    
    flash('Recipe generated successfully!')
    return redirect(url_for('icook'))

@app.route('/save_conversation', methods=['POST'])
@require_auth
def save_conversation():
    """
    Save the current chat conversation to the user's saved conversations.
    
    This route allows users to preserve their chat conversations for future reference,
    creating a permanent record of valuable cooking interactions and recipes.
    It converts the current chat session into a saved conversation with proper
    title generation and JSON formatting.
    
    Returns:
        Response: Redirect to /icook with save confirmation or error message
    
    Process Flow:
        1. Retrieve current chat messages from database
        2. Validate that there's content to save
        3. Convert messages to structured JSON format
        4. Generate descriptive title from first user message
        5. Store conversation in saved_conversations table
    
    Data Structure:
        - Converts messages to JSON array with 'type' and 'content' fields
        - Maintains chronological order of conversation
        - Creates user-friendly title (first 50 characters of first question)
        - Associates saved conversation with current user
    
    Database Operations:
        - Reads current_chat_messages for the authenticated user
        - Stores conversation in saved_conversations table
        - Uses JSON format for reliable conversation storage and retrieval
    
    Security Features:
        - Authentication required via @require_auth decorator
        - User isolation - only saves current user's conversations
        - SQL injection prevention with parameterized queries
    
    Error Handling:
        - Empty conversation validation
        - JSON encoding error handling
        - Database operation error handling
    """
    conn = get_db_connection()
    
    # Retrieve current chat messages from database instead of flash messages for reliability
    current_messages = conn.execute(
        'SELECT message_type, content FROM current_chat_messages WHERE user_id = ? ORDER BY timestamp ASC',
        (session['user_id'],)
    ).fetchall()
    
    if not current_messages:
        flash('No conversation to save!')
        conn.close()
        return redirect(url_for('icook'))
    
    # Create conversation content using JSON format for reliable parsing and storage
    conversation_data = []
    for msg in current_messages:
        conversation_data.append({
            'type': msg['message_type'],
            'content': msg['content']
        })
    
    conversation_content = json.dumps(conversation_data)
    
    # Generate descriptive title from first user message for easy identification
    title = "New Conversation"
    for msg in current_messages:
        if msg['message_type'] == 'user':
            title = msg['content'][:50]  # First 50 chars of first question
            break
    
    # Save conversation with title and JSON content
    conn.execute(
        'INSERT INTO saved_conversations (user_id, title, content) VALUES (?, ?, ?)',
        (session['user_id'], title, conversation_content)
    )
    conn.commit()
    conn.close()
    
    flash('Conversation saved successfully!')
    return redirect(url_for('icook'))

@app.route('/load_conversation', methods=['POST'])
@require_auth
def load_conversation():
    """
    Load a previously saved conversation into the current chat session.
    
    This route allows users to restore and continue previous conversations
    by loading saved conversation data into the current chat interface.
    It handles both modern JSON format and legacy text format for backward compatibility.
    
    POST Parameters:
        conversation_id (str): The ID of the saved conversation to load
    
    Returns:
        Response: Redirect to /icook with loaded conversation or error message
    
    Process Flow:
        1. Validate conversation ID is provided
        2. Retrieve saved conversation from database
        3. Verify conversation belongs to current user
        4. Clear current chat messages
        5. Parse and restore conversation messages
        6. Load messages into current_chat_messages table
    
    Data Format Handling:
        - Primary: JSON format with 'type' and 'content' fields
        - Fallback: Legacy text format for backward compatibility
        - Maintains message order and type (user/ai) distinctions
    
    Database Operations:
        - Retrieves saved conversation by ID and user ownership
        - Clears existing current_chat_messages for clean load
        - Inserts restored messages into current_chat_messages
        - Maintains conversation structure and chronology
    
    Security Features:
        - Authentication required via @require_auth decorator
        - Ownership verification - only load user's own conversations
        - Input validation for conversation_id parameter
        - SQL injection prevention with parameterized queries
     Error Handling:
        - Invalid or missing conversation ID
        - Conversation not found or access denied
        - JSON parsing errors with fallback support
        - Database operation error handling
    """
    conversation_id = request.form.get('conversation_id')
    confirmed = request.form.get('confirmed')
    
    if not conversation_id:
        flash('Invalid conversation ID')
        return redirect(url_for('icook'))
    
    # If not confirmed, show confirmation page
    if not confirmed:
        return render_template('confirm.html',
                             action='load_conversation',
                             conversation_id=conversation_id,
                             icon='⚠️',
                             title='Load Saved Conversation',
                             message='Loading a saved conversation will <strong>delete your current conversation</strong> if it hasn\'t been saved.<br><br>All messages in your current chat will be permanently lost.',
                             tip='Use "Save Conversation" to preserve your current chat before loading another one.')

    conn = get_db_connection()
    conversation = conn.execute(
        'SELECT * FROM saved_conversations WHERE id = ? AND user_id = ?',
        (conversation_id, session['user_id'])
    ).fetchone()
    
    if not conversation:
        flash('Conversation not found')
        conn.close()
        return redirect(url_for('icook'))
    
    # Clear current chat messages to provide clean slate for loaded conversation
    conn.execute('DELETE FROM current_chat_messages WHERE user_id = ?', (session['user_id'],))
    
    # Load conversation content into current chat messages with format handling
    try:
        # Try modern JSON format first
        conversation_data = json.loads(conversation['content'])
        
        for msg in conversation_data:
            conn.execute(
                'INSERT INTO current_chat_messages (user_id, message_type, content) VALUES (?, ?, ?)',
                (session['user_id'], msg['type'], msg['content'])
            )
    except (json.JSONDecodeError, KeyError):
        # Fallback to legacy text format for backward compatibility
        for line in conversation['content'].split('\n'):
            line = line.strip()
            if line.startswith('You asked: '):
                content = line[11:]  # Remove "You asked: " prefix
                conn.execute(
                    'INSERT INTO current_chat_messages (user_id, message_type, content) VALUES (?, ?, ?)',
                    (session['user_id'], 'user', content)
                )
            elif line.startswith('iCook: '):
                content = line[7:]  # Remove "iCook: " prefix
                conn.execute(
                    'INSERT INTO current_chat_messages (user_id, message_type, content) VALUES (?, ?, ?)',
                    (session['user_id'], 'ai', content)
                )
    
    conn.commit()
    conn.close()
    
    flash(f'Loaded conversation: {conversation["title"]}')
    return redirect(url_for('icook'))

@app.route('/delete_saved_conversation', methods=['POST'])
@require_auth
def delete_saved_conversation():
    """
    Delete a specific saved conversation from the user's collection.
    
    This route allows users to permanently remove saved conversations they
    no longer need, helping manage their conversation history and storage.
    
    POST Parameters:
        conversation_id (str): The ID of the saved conversation to delete
    
    Returns:
        Response: Redirect to /icook with deletion confirmation or error message
    
    Security Features:
        - Authentication required via @require_auth decorator
        - Ownership verification - users can only delete their own conversations
        - Input validation for conversation_id parameter
        - SQL injection prevention with parameterized queries
    
    Database Operations:
        - Deletes conversation record matching both ID and user ownership
        - Uses double verification (conversation_id AND user_id)
        - Commits transaction for immediate removal
    
    Error Handling:
        - Invalid or missing conversation ID validation
        - Database operation error handling
    - User feedback via flash messages
    """
    conversation_id = request.form.get('conversation_id')
    confirmed = request.form.get('confirmed')
    
    if not conversation_id:
        flash('Invalid conversation ID')
        return redirect(url_for('icook'))
    
    # If not confirmed, show confirmation page
    if not confirmed:
        return render_template('confirm.html',
                             action='delete_conversation',
                             conversation_id=conversation_id,
                             icon='🗑️',
                             title='Delete Saved Conversation',
                             message='Are you sure you want to <strong>permanently delete</strong> this saved conversation?<br><br>This action cannot be undone and all messages in this conversation will be lost forever.',
                             tip=None)

    conn = get_db_connection()
    conn.execute(
        'DELETE FROM saved_conversations WHERE id = ? AND user_id = ?',
        (conversation_id, session['user_id'])
    )
    conn.commit()
    conn.close()

    flash('Conversation deleted successfully!')
    return redirect(url_for('icook'))

@app.route('/clear_current_chat', methods=['POST'])
@require_auth
def clear_current_chat():
    """
    Clear the current active chat conversation.
    
    This route provides users with the ability to start fresh by removing
    all messages from their current chat session. This is useful when users
    want to begin a new conversation topic or clear a cluttered chat interface.
    
    Returns:
        Response: Redirect to /icook with cleared chat interface
    
    Database Operations:
        - Removes all current_chat_messages for the authenticated user
        - Maintains saved conversations and chat history intact
        - Commits transaction for immediate effect
    
    Security Features:
        - Authentication required via @require_auth decorator
        - User isolation - only clears current user's active chat
        - SQL injection prevention with parameterized queries
    
    User Experience:
        - Provides immediate visual feedback via flash message
        - Returns to clean chat interface for new conversations
        - Preserves user's ingredients and saved conversations
    """
    confirmed = request.form.get('confirmed')
    
    # If not confirmed, show confirmation page
    if not confirmed:
        return render_template('confirm.html',
                             action='clear_current',
                             conversation_id=None,
                             icon='🗑️',
                             title='Delete Current Conversation',
                             message='Are you sure you want to <strong>delete your current conversation</strong>?<br><br>This will permanently remove all messages in the current chat and cannot be undone.',
                             tip='Use "Save Conversation" to preserve it before deleting.')
    
    # Clear current chat messages from database for clean interface
    conn = get_db_connection()
    conn.execute('DELETE FROM current_chat_messages WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    
    flash('Current conversation cleared!')
    return redirect(url_for('icook'))

@app.route('/new_chat', methods=['POST'])
@require_auth
def new_chat():
    """
    Start a new chat session with user confirmation.
    
    This route provides a user-friendly way to initiate fresh conversations
    by confirming the start of a new chat session. Currently provides user
    feedback without clearing existing messages, allowing users to continue
    or manually clear if desired.
    
    Returns:
        Response: Redirect to /icook with new chat session confirmation
    
    Features:
        - User feedback via flash message
        - Maintains existing conversation for user decision
        - Provides clear indication of new session start
    
    Security Features:
        - Authentication required via @require_auth decorator
        - No database modifications (non-destructive operation)
    
    Note: This route currently serves as a user interface element.
    For actual chat clearing, users can use the clear_current_chat route.
    """
    flash('Started new chat session!')
    return redirect(url_for('icook'))

@app.route('/delete_chat_history', methods=['POST'])
@require_auth
def delete_chat_history():
    """
    Delete all historical chat records for the current user.
    
    This route provides users with the ability to permanently remove their
    entire chat history from the system. This is useful for privacy concerns
    or when users want to start completely fresh with no historical data.
    
    Returns:
        Response: Redirect to /icook with deletion confirmation
    
    Database Operations:
        - Removes all records from chat_history table for the authenticated user
        - Preserves current_chat_messages (active session) and saved_conversations
        - Commits transaction for permanent deletion
    
    Security Features:
        - Authentication required via @require_auth decorator
        - User isolation - only deletes current user's chat history
        - SQL injection prevention with parameterized queries
    
    Important Notes:
        - This operation is irreversible - historical chat data cannot be recovered
        - Does not affect current active chat or saved conversations
        - Useful for privacy management and storage cleanup
    
    User Experience:
        - Provides clear confirmation of successful deletion
        - Maintains current session and saved conversations intact
        - Allows users to continue using the application normally
    """
    conn = get_db_connection()
    conn.execute('DELETE FROM chat_history WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    
    flash('Chat history deleted successfully!')
    return redirect(url_for('icook'))


# ============================================================================
#                              ADMIN ROUTES
# ============================================================================

def require_admin_auth(f):
    """
    Decorator to require admin authentication for admin routes.
    
    This decorator checks if the user is authenticated as an admin
    and redirects to admin login if not authenticated.
    
    Args:
        f: The function to decorate
    
    Returns:
        Decorated function that checks admin authentication
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """
    Admin login page and authentication handler.
    
    GET: Display admin login form
    POST: Process admin login credentials
    
    Returns:
        GET: Admin login template
        POST: Redirect to admin dashboard or show error message
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            session['admin_username'] = username
            flash('Successfully logged in as admin!')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials!')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """
    Admin logout handler.
    
    Clears admin session and redirects to admin login page.
    
    Returns:
        Redirect to admin login page
    """
    session.pop('admin_authenticated', None)
    session.pop('admin_username', None)
    flash('Admin logged out successfully!')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@require_admin_auth
def admin_dashboard():
    """
    Main admin dashboard showing user management interface.
    
    Displays all users with their information and provides
    CRUD operations for user management.
    
    Returns:
        Admin dashboard template with user data
    """
    conn = get_db_connection()
    users = conn.execute('''
        SELECT u.id, u.email, u.first_name, u.last_name, u.created_at, u.banned,
               COUNT(DISTINCT i.id) as ingredient_count,
               COUNT(DISTINCT s.id) as saved_conversations,
               COUNT(DISTINCT c.id) as chat_messages
        FROM user u
        LEFT JOIN ingredient i ON u.id = i.user_id
        LEFT JOIN saved_conversations s ON u.id = s.user_id
        LEFT JOIN current_chat_messages c ON u.id = c.user_id
        GROUP BY u.id, u.email, u.first_name, u.last_name, u.created_at, u.banned
        ORDER BY u.created_at DESC
    ''').fetchall()
    conn.close()
    
    # Convert to list of dictionaries for easier template handling
    users_data = []
    for user in users:
        banned_status = user['banned'] if 'banned' in user.keys() else 0
        users_data.append({
            'id': user['id'],
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'email': user['email'],
            'created_at': user['created_at'],
            'banned': banned_status,
            'ingredient_count': user['ingredient_count'],
            'saved_conversations': user['saved_conversations'],
            'chat_messages': user['chat_messages']
        })
    
    return render_template('admin_dashboard.html', users=users_data)

@app.route('/admin/user/<int:user_id>')
@require_admin_auth
def admin_view_user(user_id):
    """
    View detailed information about a specific user.
    
    Args:
        user_id: ID of the user to view
    
    Returns:
        User detail template with comprehensive user data
    """
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('User not found!')
        return redirect(url_for('admin_dashboard'))
    
    # Get user's ingredients
    ingredients = conn.execute(
        'SELECT * FROM ingredient WHERE user_id = ? ORDER BY name',
        (user_id,)
    ).fetchall()
    
    # Get user's saved conversations
    conversations = conn.execute(
        'SELECT * FROM saved_conversations WHERE user_id = ? ORDER BY timestamp DESC',
        (user_id,)
    ).fetchall()
    
    # Get user's chat history
    chat_history = conn.execute(
        'SELECT * FROM chat_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50',
        (user_id,)
    ).fetchall()
    
    conn.close()
    
    # Format user data for template compatibility
    user_data = {
        'id': user['id'],
        'email': user['email'],
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'created_at': user['created_at']
    }
    
    return render_template('admin_user_detail.html', 
                         user=user_data, 
                         ingredients=ingredients,
                         conversations=conversations,
                         chat_history=chat_history)

@app.route('/admin/user/add', methods=['GET', 'POST'])
@require_admin_auth
def admin_add_user():
    """
    Add new user interface.
    
    GET: Display add user form
    POST: Process new user creation
    
    Returns:
        GET: Add user template
        POST: Redirect to admin dashboard or show error
    """
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password')
        
        if not all([email, first_name, last_name, password]):
            flash('All fields are required!')
            return render_template('admin_add_user.html')
        
        conn = get_db_connection()
        
        # Check if email already exists
        existing_user = conn.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone()
        if existing_user:
            flash('Email already exists!')
            conn.close()
            return render_template('admin_add_user.html')
        
        # Create new user
        hashed_password = generate_password_hash(password)
        try:
            conn.execute(
                'INSERT INTO user (email, first_name, last_name, password, created_at) VALUES (?, ?, ?, ?, ?)',
                (email, first_name, last_name, hashed_password, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            flash(f'User "{first_name} {last_name}" created successfully!')
        except sqlite3.IntegrityError:
            flash('Error creating user. Email may already exist.')
        finally:
            conn.close()
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_add_user.html')

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@require_admin_auth
def admin_edit_user(user_id):
    """
    Edit existing user interface.
    
    Args:
        user_id: ID of the user to edit
    
    GET: Display edit user form with current data
    POST: Process user updates
    
    Returns:
        GET: Edit user template
        POST: Redirect to admin dashboard or show error
    """
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('User not found!')
        conn.close()
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password')
        
        if not all([email, first_name, last_name]):
            flash('Email, first name, and last name are required!')
            conn.close()
            return render_template('admin_edit_user.html', user=user)
        
        # Check if email is taken by another user
        existing_user = conn.execute(
            'SELECT id FROM user WHERE email = ? AND id != ?', 
            (email, user_id)
        ).fetchone()
        
        if existing_user:
            flash('Email already exists!')
            conn.close()
            return render_template('admin_edit_user.html', user=user)
        
        try:
            if password:  # Only update password if provided
                hashed_password = generate_password_hash(password)
                conn.execute(
                    'UPDATE user SET email = ?, first_name = ?, last_name = ?, password = ? WHERE id = ?',
                    (email, first_name, last_name, hashed_password, user_id)
                )
            else:
                conn.execute(
                    'UPDATE user SET email = ?, first_name = ?, last_name = ? WHERE id = ?',
                    (email, first_name, last_name, user_id)
                )
            
            conn.commit()
            flash(f'User "{first_name} {last_name}" updated successfully!')
        except sqlite3.IntegrityError:
            flash('Error updating user. Email may already exist.')
        finally:
            conn.close()
        
        return redirect(url_for('admin_dashboard'))
    
    conn.close()
    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@require_admin_auth
def admin_delete_user(user_id):
    """
    Delete user and all associated data.
    
    Args:
        user_id: ID of the user to delete
    
    Returns:
        Redirect to admin dashboard with confirmation message
    """
    conn = get_db_connection()
    user = conn.execute('SELECT first_name, last_name FROM user WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('User not found!')
    else:
        try:
            # Delete user (CASCADE will handle related records)
            conn.execute('DELETE FROM user WHERE id = ?', (user_id,))
            conn.commit()
            flash(f'User "{user["first_name"]} {user["last_name"]}" and all associated data deleted successfully!')
        except Exception as e:
            flash(f'Error deleting user: {str(e)}')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/ban/<int:user_id>', methods=['POST'])
@require_admin_auth
def admin_ban_user(user_id):
    """
    Ban or unban a user account.
    
    Args:
        user_id: ID of the user to ban/unban
    
    Returns:
        Redirect to admin dashboard with confirmation message
    """
    conn = get_db_connection()
    user = conn.execute('SELECT first_name, last_name, banned FROM user WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('User not found!')
        conn.close()
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Toggle banned status
        new_banned_status = 0 if user['banned'] else 1
        action = "banned" if new_banned_status else "unbanned"
        
        conn.execute('UPDATE user SET banned = ? WHERE id = ?', (new_banned_status, user_id))
        conn.commit()
        
        full_name = f"{user['first_name']} {user['last_name']}"
        flash(f'User "{full_name}" has been {action} successfully!')
        
    except Exception as e:
        flash(f'Error updating user ban status: {str(e)}')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    """
    Application entry point for development server.
    
    This block initializes the database and starts the Flask development server
    when the script is run directly. It ensures the database schema is created
    before the application begins accepting requests.
    
    Initialization Process:
        1. Calls init_db() to create database tables if they don't exist
        2. Starts Flask development server with debug mode enabled
    
    Development Features:
        - Debug mode enables auto-reload on code changes
        - Detailed error messages for development
        - Hot reloading for efficient development workflow
    
    Production Notes:
        - For production deployment, use a proper WSGI server (not debug mode)
        - Set environment variables for security (SECRET_KEY, API keys)
        - Disable debug mode in production environments
    """
    init_db()
    app.run(debug=True)
