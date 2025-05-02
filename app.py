from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import secrets
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Secure random key

def init_db():
    conn = sqlite3.connect('experiences.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT 0
    )''')
    
    # Create experiences table with additional fields
    c.execute('''CREATE TABLE IF NOT EXISTS experiences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        company TEXT NOT NULL,
        role TEXT NOT NULL,
        tags TEXT,
        difficulty INTEGER,
        experience TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('experiences.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.context_processor
def inject_csrf_token():
    return {'csrf_token': secrets.token_hex(16)}

@app.route('/')
def home():
    search = request.args.get('search', '')
    tag_filter = request.args.get('tag', '')
    difficulty_filter = request.args.get('difficulty', '')
    
    conn = get_db_connection()
    
    # Get unique companies for the datalist
    unique_companies = [row[0] for row in conn.execute("SELECT DISTINCT company FROM experiences").fetchall()]
    
    query = '''SELECT experiences.*, users.username 
               FROM experiences 
               JOIN users ON experiences.user_id = users.id'''
    params = []
    
    conditions = []
    if search:
        conditions.append("(company LIKE ? OR role LIKE ? OR experience LIKE ?)")
        params.extend(['%' + search + '%'] * 3)
    if tag_filter:
        conditions.append("tags LIKE ?")
        params.append('%' + tag_filter + '%')
    if difficulty_filter:
        conditions.append("difficulty = ?")
        params.append(difficulty_filter)
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    query += " ORDER BY created_at DESC"
    experiences = conn.execute(query, params).fetchall()
    
    # Get unique tags for filter
    tags = conn.execute("SELECT DISTINCT tags FROM experiences WHERE tags IS NOT NULL").fetchall()
    all_tags = set()
    for tag in tags:
        if tag['tags']:
            all_tags.update(t.strip() for t in tag['tags'].split(','))
    
    conn.close()
    
    return render_template('index.html', 
                         experiences=experiences,
                         search_query=search,
                         all_tags=sorted(all_tags),
                         selected_tag=tag_filter,
                         selected_difficulty=difficulty_filter,
                         unique_companies=unique_companies)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        conn = get_db_connection()
        try:
            hashed_password = generate_password_hash(password)
            conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                        (username, email, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash('Logged in successfully!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        name = request.form['name']
        company = request.form['company']
        role = request.form['role']
        tags = request.form['tags']
        difficulty = request.form['difficulty']
        experience = request.form['experience']
        
        conn = get_db_connection()
        conn.execute('''INSERT INTO experiences 
                       (user_id, name, company, role, tags, difficulty, experience) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (session['user_id'], name, company, role, tags, difficulty, experience))
        conn.commit()
        conn.close()
        
        flash('Experience submitted successfully!', 'success')
        return redirect(url_for('home'))
    
    return render_template('submit.html')

@app.route('/my_experiences')
@login_required
def my_experiences():
    conn = get_db_connection()
    experiences = conn.execute('''SELECT * FROM experiences 
                                WHERE user_id = ? 
                                ORDER BY created_at DESC''',
                             (session['user_id'],)).fetchall()
    conn.close()
    return render_template('my_experiences.html', experiences=experiences)

@app.route('/experience/<int:exp_id>')
def view_experience(exp_id):
    conn = get_db_connection()
    experience = conn.execute('''SELECT experiences.*, users.username 
                               FROM experiences 
                               JOIN users ON experiences.user_id = users.id
                               WHERE experiences.id = ?''', (exp_id,)).fetchone()
    conn.close()
    
    if not experience:
        flash('Experience not found', 'danger')
        return redirect(url_for('home'))
    
    return render_template('experience_detail.html', experience=experience)

@app.route('/experience/delete/<int:exp_id>', methods=['POST'])
@login_required
def delete_experience(exp_id):
    # Simple CSRF check
    if request.method != 'POST':
        flash('Invalid request method', 'danger')
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    experience = conn.execute('SELECT * FROM experiences WHERE id = ? AND user_id = ?',
                            (exp_id, session['user_id'])).fetchone()
    
    if not experience:
        flash('Experience not found or you are not authorized to delete it', 'danger')
        return redirect(url_for('home'))
    
    conn.execute('DELETE FROM experiences WHERE id = ?', (exp_id,))
    conn.commit()
    conn.close()
    
    flash('Experience deleted successfully', 'success')
    return redirect(url_for('my_experiences'))

@app.route('/experience/edit/<int:exp_id>', methods=['GET', 'POST'])
@login_required
def edit_experience(exp_id):
    conn = get_db_connection()
    
    if request.method == 'GET':
        experience = conn.execute('''SELECT * FROM experiences 
                                   WHERE id = ? AND user_id = ?''',
                                (exp_id, session['user_id'])).fetchone()
        conn.close()
        
        if not experience:
            flash('Experience not found or you are not authorized to edit it', 'danger')
            return redirect(url_for('my_experiences'))
        
        return render_template('edit_experience.html', experience=experience)
    
    elif request.method == 'POST':
        # Verify experience belongs to current user
        experience = conn.execute('SELECT * FROM experiences WHERE id = ? AND user_id = ?',
                                (exp_id, session['user_id'])).fetchone()
        
        if not experience:
            conn.close()
            flash('Experience not found or you are not authorized to edit it', 'danger')
            return redirect(url_for('my_experiences'))
        
        # Update the experience
        name = request.form['name']
        company = request.form['company']
        role = request.form['role']
        tags = request.form['tags']
        difficulty = request.form['difficulty']
        experience_text = request.form['experience']
        
        conn.execute('''UPDATE experiences SET 
                       name = ?, company = ?, role = ?, 
                       tags = ?, difficulty = ?, experience = ?
                       WHERE id = ?''',
                    (name, company, role, tags, difficulty, experience_text, exp_id))
        conn.commit()
        conn.close()
        
        flash('Experience updated successfully!', 'success')
        return redirect(url_for('view_experience', exp_id=exp_id))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)