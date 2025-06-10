from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import sqlite3
import hashlib # For password hashing

app = Flask(__name__)
app.secret_key = 'your_new_super_secret_key_here' # IMPORTANT: Change this to a strong, random key!

DATABASE = 'hacker_leaderboard.db'

# --- Database setup and helper functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row # This makes rows behave like dictionaries
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS leaderboard (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                country TEXT NOT NULL,
                challenges_completed INTEGER DEFAULT 0,
                respect INTEGER DEFAULT 0,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                liker_user_id INTEGER NOT NULL,
                liked_leaderboard_id INTEGER NOT NULL,
                FOREIGN KEY (liker_user_id) REFERENCES users (id),
                FOREIGN KEY (liked_leaderboard_id) REFERENCES leaderboard (id),
                UNIQUE(liker_user_id, liked_leaderboard_id)
            )
        ''')

        # Add admin user if not exists
        admin_username = 'admin'
        admin_password_hash = hashlib.sha256('super_secure_admin_password'.encode()).hexdigest() # IMPORTANT: Use a strong password!
        try:
            db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                       (admin_username, admin_password_hash, 1))
            db.commit()
            print("Admin user created.")
        except sqlite3.IntegrityError:
            print("Admin user already exists.")
        db.commit() # Commit changes to users table if admin was added

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(hashed_password, user_password):
    return hashed_password == hashlib.sha256(user_password.encode()).hexdigest()

def get_rank(challenges_completed):
    # Ensure challenges_completed is treated as an integer for comparison
    challenges_completed = int(challenges_completed)

    if challenges_completed >= 30:
        return "Legend"
    elif challenges_completed >= 20:
        return "Guru"
    elif challenges_completed >= 12:
        return "Elite Hacker"
    elif challenges_completed >= 6:
        return "Pro Hacker"
    elif challenges_completed >= 3:
        return "Hacker"
    else: # Covers 0, 1, 2
        return "Script Kiddie"

# --- Routes ---

@app.route('/')
def index():
    db = get_db()
    leaderboard_entries = db.execute('SELECT * FROM leaderboard ORDER BY respect DESC, challenges_completed DESC').fetchall()
    # db.close() # REMOVED

    leaderboard_data = []
    current_user_id = session.get('user_id')

    for entry in leaderboard_entries:
        entry_dict = dict(entry) # Convert Row object to dictionary
        entry_dict['rank'] = get_rank(entry_dict['challenges_completed'])

        if current_user_id:
            # No need to call get_db() again here, as db from above is still valid for this request
            has_liked = db.execute(
                'SELECT 1 FROM likes WHERE liker_user_id = ? AND liked_leaderboard_id = ?',
                (current_user_id, entry_dict['id'])
            ).fetchone()
            # db.close() # REMOVED
            entry_dict['has_liked'] = bool(has_liked) # True if a row was found
        else:
            entry_dict['has_liked'] = False

        leaderboard_data.append(entry_dict)

    return render_template('index.html', leaderboard=leaderboard_data)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        country = request.form['country']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return render_template('register.html')

        hashed_password = hash_password(password)

        db = get_db()
        try:
            # Insert into users table
            cursor = db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                               (username, hashed_password))
            user_id = cursor.lastrowid # Get the ID of the newly created user

            # Also create an entry in the leaderboard table WITH country
            db.execute("INSERT INTO leaderboard (username, country, challenges_completed, respect, user_id) VALUES (?, ?, ?, ?, ?)",
                       (username, country, 0, 0, user_id))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
        # finally: # REMOVED finally block with db.close()
            # db.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        # db.close() # REMOVED

        if user and check_password(user['password'], password):
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if not session.get('logged_in'):
        flash('You need to be logged in to edit your profile.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()

    if request.method == 'POST':
        new_challenges = request.form['challenges_completed']
        new_country = request.form['country']
        
        db.execute('UPDATE leaderboard SET challenges_completed = ?, country = ? WHERE user_id = ?',
                   (new_challenges, new_country, user_id))
        db.commit()
        flash('Your profile has been updated!', 'success')
        # db.close() # REMOVED
        return redirect(url_for('index'))
    else:
        profile_data = db.execute('SELECT * FROM leaderboard WHERE user_id = ?', (user_id,)).fetchone()
        # db.close() # REMOVED
        if profile_data:
            return render_template('edit_profile.html', profile=dict(profile_data))
        else:
            flash('Profile data not found.', 'danger')
            return redirect(url_for('index'))


@app.route('/respect/<int:leaderboard_entry_id>', methods=['POST'])
def respect_entry(leaderboard_entry_id):
    if not session.get('logged_in'):
        flash('You need to be logged in to give respect.', 'danger')
        return redirect(url_for('login'))

    liker_user_id = session['user_id']
    db = get_db()

    try:
        # Check if user has already liked this entry
        existing_like = db.execute(
            'SELECT 1 FROM likes WHERE liker_user_id = ? AND liked_leaderboard_id = ?',
            (liker_user_id, leaderboard_entry_id)
        ).fetchone()

        if existing_like:
            flash('You have already given respect to this entry.', 'warning')
        else:
            # Add a like record
            db.execute(
                'INSERT INTO likes (liker_user_id, liked_leaderboard_id) VALUES (?, ?)',
                (liker_user_id, leaderboard_entry_id)
            )
            # Increment respect count in leaderboard
            db.execute(
                'UPDATE leaderboard SET respect = respect + 1 WHERE id = ?',
                (leaderboard_entry_id,)
            )
            db.commit()
            flash('Respect given!', 'success')
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')
    # finally: # REMOVED finally block with db.close()
        # db.close()
    return redirect(url_for('index'))


# --- Admin Panel Routes ---

@app.before_request
def check_admin_privileges():
    # List of admin-only endpoints (prefix 'admin_')
    admin_endpoints = [
        'admin_panel', 'admin_add_leaderboard', 'admin_edit_leaderboard',
        'admin_delete_leaderboard', 'admin_add_user', 'admin_edit_user', 'admin_delete_user'
    ]
    if request.endpoint and request.endpoint in admin_endpoints and not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))


@app.route('/admin')
def admin_panel():
    db = get_db()
    leaderboard_entries = db.execute('SELECT * FROM leaderboard').fetchall()
    users = db.execute('SELECT * FROM users').fetchall()
    # db.close() # REMOVED
    return render_template('admin.html', leaderboard_entries=leaderboard_entries, users=users)

# Admin - Add Leaderboard Entry
@app.route('/admin/leaderboard/add', methods=['GET', 'POST'])
def admin_add_leaderboard():
    if request.method == 'POST':
        username = request.form['username']
        country = request.form['country']
        challenges_completed = request.form.get('challenges_completed', 0)
        respect = request.form.get('respect', 0)

        db = get_db()
        try:
            # Check if a user with this username already exists in 'users'
            # If so, link to that user_id. If not, create a placeholder user in 'users'.
            user_in_users = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            user_id = None
            if user_in_users:
                user_id = user_in_users['id']
            else:
                # Create a minimal user entry if username not in users, for consistency
                # This account won't have a password for login, it's just a placeholder
                temp_user_cursor = db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                                             (username, 'temp_no_login_password', 0))
                user_id = temp_user_cursor.lastrowid


            db.execute("INSERT INTO leaderboard (username, country, challenges_completed, respect, user_id) VALUES (?, ?, ?, ?, ?)",
                       (username, country, challenges_completed, respect, user_id))
            db.commit()
            flash('Leaderboard entry added!', 'success')
            return redirect(url_for('admin_panel'))
        except sqlite3.IntegrityError:
            flash('Username already exists in leaderboard.', 'danger')
        # finally: # REMOVED finally block with db.close()
            # db.close()
    return render_template('admin_add_leaderboard.html')

# Admin - Edit Leaderboard Entry
@app.route('/admin/leaderboard/edit/<int:entry_id>', methods=['GET', 'POST'])
def admin_edit_leaderboard(entry_id):
    db = get_db()
    entry = db.execute('SELECT * FROM leaderboard WHERE id = ?', (entry_id,)).fetchone()

    if not entry:
        flash('Leaderboard entry not found.', 'danger')
        # db.close() # REMOVED
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        new_username = request.form['username']
        new_country = request.form['country']
        new_challenges = request.form['challenges_completed']
        new_respect = request.form['respect']

        try:
            db.execute('UPDATE leaderboard SET username = ?, country = ?, challenges_completed = ?, respect = ? WHERE id = ?',
                       (new_username, new_country, new_challenges, new_respect, entry_id))
            # Also update username in users table if linked
            if entry['user_id']:
                db.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, entry['user_id']))
            db.commit()
            flash('Leaderboard entry updated!', 'success')
            return redirect(url_for('admin_panel'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
        # finally: # REMOVED finally block with db.close()
            # db.close()
    return render_template('admin_edit_leaderboard.html', entry=dict(entry))

# Admin - Delete Leaderboard Entry
@app.route('/admin/leaderboard/delete/<int:entry_id>', methods=['POST'])
def admin_delete_leaderboard(entry_id):
    db = get_db()
    try:
        # Delete associated likes first to avoid foreign key constraints
        db.execute('DELETE FROM likes WHERE liked_leaderboard_id = ?', (entry_id,))
        db.execute('DELETE FROM leaderboard WHERE id = ?', (entry_id,))
        db.commit()
        flash('Leaderboard entry deleted!', 'success')
    except Exception as e:
        flash(f'Error deleting entry: {e}', 'danger')
    # finally: # REMOVED finally block with db.close()
        # db.close()
    return redirect(url_for('admin_panel'))

# Admin - Add User
@app.route('/admin/user/add', methods=['GET', 'POST'])
def admin_add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        country = request.form.get('country', 'Unknown')
        is_admin = 1 if request.form.get('is_admin') else 0
        hashed_password = hash_password(password)

        db = get_db()
        try:
            cursor = db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                               (username, hashed_password, is_admin))
            user_id = cursor.lastrowid
            
            # Also create a corresponding leaderboard entry if it doesn't exist
            # This handles cases where you add a user directly via admin panel
            existing_leaderboard_entry = db.execute('SELECT id FROM leaderboard WHERE user_id = ?', (user_id,)).fetchone()
            if not existing_leaderboard_entry:
                 # Default country and 0 challenges/respect for new user
                db.execute("INSERT INTO leaderboard (username, country, challenges_completed, respect, user_id) VALUES (?, ?, ?, ?, ?)",
                            (username, country, 0, 0, user_id))
            db.commit()
            flash('User added!', 'success')
            return redirect(url_for('admin_panel'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        # finally: # REMOVED finally block with db.close()
            # db.close()
    return render_template('admin_add_user.html')

# Admin - Edit User
@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    linked_leaderboard_entry = db.execute('SELECT country FROM leaderboard WHERE user_id = ?', (user_id,)).fetchone()

    if not user:
        flash('User not found.', 'danger')
        # db.close() # REMOVED
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form['password']
        new_country = request.form.get('country', 'Unknown')
        new_is_admin = 1 if request.form.get('is_admin') else 0

        try:
            # Update username and admin status
            db.execute('UPDATE users SET username = ?, is_admin = ? WHERE id = ?',
                       (new_username, new_is_admin, user_id))
            # If password provided, update it
            if new_password:
                hashed_password = hash_password(new_password)
                db.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))

            # Also update username and country in linked leaderboard entry
            db.execute('UPDATE leaderboard SET username = ?, country = ? WHERE user_id = ?', (new_username, new_country, user_id))
            db.commit()
            flash('User updated!', 'success')
            return redirect(url_for('admin_panel'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        # finally: # REMOVED finally block with db.close()
            # db.close()
    return render_template('admin_edit_user.html', user=dict(user), linked_country=linked_leaderboard_entry['country'] if linked_leaderboard_entry else 'Unknown')

# Admin - Delete User
@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot delete your own admin account.', 'danger')
        return redirect(url_for('admin_panel'))

    db = get_db()
    try:
        # Get leaderboard entry ID linked to this user
        leaderboard_entry_id = db.execute('SELECT id FROM leaderboard WHERE user_id = ?', (user_id,)).fetchone()
        if leaderboard_entry_id:
            # Delete associated likes for the leaderboard entry
            db.execute('DELETE FROM likes WHERE liked_leaderboard_id = ?', (leaderboard_entry_id[0],))
            # Delete the leaderboard entry itself
            db.execute('DELETE FROM leaderboard WHERE user_id = ?', (user_id,))
        
        # Delete any likes *this user* has made
        db.execute('DELETE FROM likes WHERE liker_user_id = ?', (user_id,))
        
        # Finally, delete the user
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        flash('User deleted!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {e}', 'danger')
    # finally: # REMOVED finally block with db.close()
        # db.close()
    return redirect(url_for('admin_panel'))


if __name__ == '__main__':
    with app.app_context():
        init_db() # Ensure DB is initialized before running the app
    app.run(debug=True)