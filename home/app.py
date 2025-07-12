from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import sqlite3
import uuid
import os
import hashlib
from datetime import datetime
from functools import wraps

# AWS imports (conditional)
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

# Load environment variables (optional)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, use system environment variables

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'pickle-secret-key-2025')

# AWS Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@pickles.com')
USE_AWS = os.environ.get('USE_AWS', 'False').lower() == 'true'

# Override USE_AWS if no valid AWS credentials
try:
    if USE_AWS and AWS_AVAILABLE:
        # Test AWS credentials
        test_sts = boto3.client('sts', region_name=AWS_REGION)
        test_sts.get_caller_identity()
except:
    USE_AWS = False  # Force local mode if AWS credentials invalid

# Database configuration
if USE_AWS and AWS_AVAILABLE:
    # Production: Use DynamoDB
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    sns = boto3.client('sns', region_name=AWS_REGION)
    ses = boto3.client('ses', region_name=AWS_REGION)
    
    # DynamoDB tables
    user_table = dynamodb.Table('PickleUsers')
    order_table = dynamodb.Table('PickleOrders')
    contact_table = dynamodb.Table('PickleContacts')
else:
    # Local development: Use SQLite
    USE_AWS = False  # Force local mode if AWS not available
    def init_db():
        conn = sqlite3.connect('users.db')
        # Drop and recreate table to fix column names
        conn.execute('DROP TABLE IF EXISTS users')
        conn.execute('CREATE TABLE users (email TEXT PRIMARY KEY, name TEXT, password TEXT, created_at TEXT, status TEXT)')
        conn.close()
    init_db()

def hash_password(password):
    """Hash password for secure storage"""
    return hashlib.sha256(password.encode()).hexdigest()

def send_email_notification(to_email, subject, message):
    """Send email via SNS and SES"""
    try:
        if USE_AWS and AWS_AVAILABLE:
            # Production: Use AWS SNS and SES
            if SNS_TOPIC_ARN:
                sns.publish(TopicArn=SNS_TOPIC_ARN, Message=message, Subject=subject)
            
            ses.send_email(
                Source=ADMIN_EMAIL,
                Destination={'ToAddresses': [to_email]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {'Text': {'Data': message}}
                }
            )
        else:
            # Local development: Print to console
            print(f"EMAIL TO: {to_email}")
            print(f"SUBJECT: {subject}")
            print(f"MESSAGE: {message}")
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def get_instance_info():
    """Get EC2 instance metadata"""
    try:
        import urllib.request
        response = urllib.request.urlopen('http://169.254.169.254/latest/meta-data/instance-id', timeout=2)
        return response.read().decode('utf-8')
    except:
        return 'local'

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        try:
            name = request.form['name']
            email = request.form['email']
            message = request.form['message']
            contact_id = str(uuid.uuid4())
            timestamp = datetime.utcnow().isoformat()
            
            if USE_AWS:
                # Production: Save to DynamoDB
                contact_table.put_item(Item={
                    'contact_id': contact_id,
                    'name': name,
                    'email': email,
                    'message': message,
                    'timestamp': timestamp,
                    'status': 'new'
                })
            
            # Send email notifications
            admin_message = f"New Contact Inquiry\n\nFrom: {name}\nEmail: {email}\nMessage: {message}"
            customer_message = f"Dear {name},\n\nThank you for contacting us! We have received your message and will get back to you soon.\n\nYour Message: {message}\n\nBest regards,\nHomemade Pickles & Snacks Team"
            
            send_email_notification(ADMIN_EMAIL, 'New Contact Inquiry', admin_message)
            send_email_notification(email, 'Thank you for contacting us', customer_message)
            
            flash('Thank you for contacting us! We will get back to you soon.', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            flash(f'Message sending failed: {str(e)}', 'error')
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['username']
            password = request.form['password']
            hashed_password = hash_password(password)

            if USE_AWS:
                # Production: Use DynamoDB
                response = user_table.get_item(Key={'email': email})
                if 'Item' in response:
                    user = response['Item']
                    if user['password'] == hashed_password:
                        session['user_email'] = email
                        session['user_name'] = user['name']
                        return redirect(url_for('home'))
            else:
                # Local development: Use SQLite
                conn = sqlite3.connect('users.db')
                user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                conn.close()
                
                if user and user[2] == hashed_password:
                    session['user_email'] = email
                    session['user_name'] = user[1]
                    return redirect(url_for('home'))
            
            flash('Invalid email or password', 'error')
        except Exception as e:
            flash(f'Login failed: {str(e)}', 'error')
    return render_template('login.html')

@app.route('/create_test_user')
def create_test_user():
    try:
        hashed_password = hash_password('test123')
        conn = sqlite3.connect('users.db')
        conn.execute('INSERT OR REPLACE INTO users (email, name, password, created_at, status) VALUES (?, ?, ?, ?, ?)', 
                    ('test@test.com', 'testuser', hashed_password, datetime.utcnow().isoformat(), 'active'))
        conn.commit()
        conn.close()
        return 'Test user created: email=test@test.com, password=test123'
    except Exception as e:
        return f'Error: {e}'

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            name = request.form['fullname']
            email = request.form['email']
            password = request.form['password']
            hashed_password = hash_password(password)
            timestamp = datetime.utcnow().isoformat()

            if USE_AWS:
                # Production: Use DynamoDB
                response = user_table.get_item(Key={'email': email})
                if 'Item' in response:
                    flash('User already exists', 'error')
                    return render_template('signup.html')

                user_table.put_item(Item={
                    'email': email,
                    'name': name,
                    'password': hashed_password,
                    'created_at': timestamp,
                    'status': 'active'
                })
            else:
                # Local development: Use SQLite
                conn = sqlite3.connect('users.db')
                existing = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                if existing:
                    flash('User already exists', 'error')
                    conn.close()
                    return render_template('signup.html')

                conn.execute('INSERT INTO users (email, name, password, created_at, status) VALUES (?, ?, ?, ?, ?)', 
                            (email, name, hashed_password, timestamp, 'active'))
                conn.commit()
                conn.close()
            
            # Send welcome email
            welcome_message = f"Dear {name},\n\nWelcome to Homemade Pickles & Snacks!\n\nYour account has been created successfully.\n\nThank you!"
            send_email_notification(email, 'Welcome to Homemade Pickles & Snacks!', welcome_message)
            
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Signup failed: {str(e)}', 'error')
    return render_template('signup.html')

@app.route('/order-success')
@login_required
def order_success():
    return render_template('order_success.html')

@app.route('/cart')
@login_required
def cart():
    return render_template('cart.html')

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if request.method == 'POST':
        try:
            name = request.form['fullName']
            email = request.form['email']
            phone = request.form['phone']
            address = request.form['address']
            notes = request.form.get('notes', '')
            order_id = str(uuid.uuid4())
            timestamp = datetime.utcnow().isoformat()

            if USE_AWS:
                # Production: Save to DynamoDB
                order_table.put_item(Item={
                    'order_id': order_id,
                    'name': name,
                    'email': email,
                    'phone': phone,
                    'address': address,
                    'notes': notes,
                    'timestamp': timestamp,
                    'status': 'checkout_completed',
                    'source': 'checkout'
                })

            # Send confirmation emails
            customer_message = f"Dear {name},\n\nYour checkout is complete!\n\nOrder ID: {order_id}\nWe'll process your order and contact you soon.\n\nThank you!"
            send_email_notification(email, 'Checkout Confirmation', customer_message)
            
            session['last_order_id'] = order_id
            return redirect(url_for('order_success'))
        except Exception as e:
            flash(f'Checkout failed: {str(e)}', 'error')
    return render_template('checkout.html')

@app.route('/order', methods=['GET', 'POST'])
@login_required
def order():
    if request.method == 'POST':
        try:
            name = request.form['name']
            email = request.form['email']
            phone = request.form['phone']
            address = request.form['address']
            city = request.form.get('city', '')
            pincode = request.form.get('pincode', '')
            item = request.form['item']
            quantity = int(request.form['quantity'])
            notes = request.form.get('notes', '')
            order_id = str(uuid.uuid4())

            # Send email notifications
            customer_message = f"Dear {name},\n\nYour order has been placed successfully!\n\nOrder ID: {order_id}\nItem: {item}\nQuantity: {quantity}\n\nWe'll contact you soon for delivery details.\n\nThank you for choosing Homemade Pickles & Snacks!"
            admin_message = f"New Order Received!\n\nOrder ID: {order_id}\nCustomer: {name}\nEmail: {email}\nPhone: {phone}\nItem: {item}\nQuantity: {quantity}\nAddress: {address}, {city} - {pincode}\nNotes: {notes}"
            
            send_email_notification(email, 'Order Confirmation - Homemade Pickles & Snacks', customer_message)
            send_email_notification('admin@pickles.com', f'New Order - {order_id}', admin_message)

            session['last_order_id'] = order_id
            return redirect(url_for('order_success'))
        except Exception as e:
            flash(f'Order processing failed: {str(e)}', 'error')
            return render_template('order.html')
    return render_template('order.html')

@app.route('/snackes')
@login_required
def snackes():
    return render_template('snackes.html')

@app.route('/notify')
def notify():
    # Send a sample notification
    send_email_notification('admin@pickles.com', 'New Pickle Order Alert', 'A new order was received on Homemade Pickles & Snacks!')
    return "Notification sent!"

@app.route('/aws-info')
def aws_info():
    """Display system information"""
    try:
        # Get instance info
        instance_id = get_instance_info()
        
        # Test database connectivity
        try:
            conn = sqlite3.connect('users.db')
            conn.execute('SELECT 1')
            conn.close()
            db_status = 'Connected'
        except:
            db_status = 'Error'
        
        info = {
            'instance_id': instance_id,
            'database_status': db_status,
            'database_type': 'SQLite',
            'status': 'Running'
        }
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint for load balancer"""
    try:
        # Test database connectivity
        conn = sqlite3.connect('users.db')
        conn.execute('SELECT 1')
        conn.close()
        return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/test-email')
def test_email():
    """Test email functionality"""
    try:
        test_message = f"Test email sent at {datetime.utcnow().isoformat()}"
        result = send_email_notification('admin@pickles.com', 'Test Email', test_message)
        return jsonify({'email_sent': result, 'timestamp': datetime.utcnow().isoformat()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.route('/veg_pickles')
@login_required
def veg_pickles():
    return render_template('veg_pickles.html')

@app.route('/non_veg_pickles')
@login_required
def non_veg_pickles():
    return render_template('non_veg_pickles.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)