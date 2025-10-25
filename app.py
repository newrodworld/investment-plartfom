from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///investment.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    theme = db.Column(db.String(10), default='light')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    shipping_cost = db.Column(db.Float, nullable=False)
    taxes = db.Column(db.Float, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='active')
    return_percentage = db.Column(db.Float, default=20.0)
    timeframe = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    beneficiary = db.relationship('User', backref=db.backref('products', lazy=True))

class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    investor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    amount_invested = db.Column(db.Float, nullable=False)
    expected_return = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    investor = db.relationship('User', backref=db.backref('investments', lazy=True))
    product = db.relationship('Product', backref=db.backref('investments', lazy=True))

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='completed')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        return user
    admin = Admin.query.get(int(user_id))
    return admin

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password) and user.is_active:
        login_user(user)
        return jsonify({'success': True, 'message': 'Login successful'})
    
    return jsonify({'success': False, 'message': 'Invalid username or password'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already exists'})
    
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role=role)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Registration successful'})

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Admin Routes
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Default admin credentials (change in production)
    if username == 'admin' and password == 'admin123':
        admin = Admin.query.filter_by(username='admin').first()
        if not admin:
            hashed_password = generate_password_hash('admin123')
            admin = Admin(username='admin', password=hashed_password)
            db.session.add(admin)
            db.session.commit()
        
        login_user(admin)
        return jsonify({'success': True, 'message': 'Admin login successful'})
    
    return jsonify({'success': False, 'message': 'Invalid admin credentials'})

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not Admin.query.get(current_user.id):
        return redirect('/admin')
    return render_template('admin_dashboard.html')

@app.route('/api/admin/users')
@login_required
def get_all_users():
    if not Admin.query.get(current_user.id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = User.query.all()
    users_data = []
    for user in users:
        users_data.append({
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'balance': user.balance,
            'is_active': user.is_active,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M'),
            'products_count': len(user.products),
            'investments_count': len(user.investments)
        })
    return jsonify(users_data)

@app.route('/api/admin/update_user', methods=['POST'])
@login_required
def update_user():
    if not Admin.query.get(current_user.id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    user_id = data.get('user_id')
    field = data.get('field')
    value = data.get('value')
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    if field == 'balance':
        user.balance = float(value)
    elif field == 'is_active':
        user.is_active = bool(value)
    elif field == 'password':
        user.password = generate_password_hash(value)
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'User updated successfully'})

@app.route('/api/admin/transactions')
@login_required
def get_all_transactions():
    if not Admin.query.get(current_user.id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    transactions = Transaction.query.order_by(Transaction.created_at.desc()).limit(50).all()
    transactions_data = []
    for transaction in transactions:
        transactions_data.append({
            'id': transaction.id,
            'username': transaction.user.username,
            'amount': transaction.amount,
            'type': transaction.transaction_type,
            'date': transaction.created_at.strftime('%Y-%m-%d %H:%M'),
            'status': transaction.status
        })
    return jsonify(transactions_data)

@app.route('/api/admin/products')
@login_required
def get_all_products():
    if not Admin.query.get(current_user.id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    products = Product.query.all()
    products_data = []
    for product in products:
        products_data.append({
            'id': product.id,
            'name': product.name,
            'beneficiary': product.beneficiary.username,
            'total_amount': product.total_amount,
            'status': product.status,
            'return_percentage': product.return_percentage,
            'timeframe': product.timeframe,
            'created_at': product.created_at.strftime('%Y-%m-%d %H:%M'),
            'investments_count': len(product.investments)
        })
    return jsonify(products_data)

# Existing API routes
@app.route('/api/user')
@login_required
def get_user():
    return jsonify({
        'username': current_user.username,
        'role': current_user.role,
        'balance': current_user.balance,
        'theme': current_user.theme
    })

@app.route('/api/update_theme', methods=['POST'])
@login_required
def update_theme():
    data = request.get_json()
    current_user.theme = data['theme']
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/products')
@login_required
def get_products():
    products = Product.query.filter_by(status='active').all()
    products_data = []
    for product in products:
        products_data.append({
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'total_amount': product.total_amount,
            'return_percentage': product.return_percentage,
            'timeframe': product.timeframe,
            'beneficiary': product.beneficiary.username,
            'investment_needed': product.total_amount * 0.5
        })
    return jsonify(products_data)

@app.route('/api/my_products')
@login_required
def get_my_products():
    if current_user.role != 'beneficiary':
        return jsonify([])
    
    products = Product.query.filter_by(beneficiary_id=current_user.id).all()
    products_data = []
    for product in products:
        products_data.append({
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'total_amount': product.total_amount,
            'status': product.status,
            'return_percentage': product.return_percentage,
            'timeframe': product.timeframe,
            'created_at': product.created_at.strftime('%Y-%m-%d')
        })
    return jsonify(products_data)

@app.route('/api/create_product', methods=['POST'])
@login_required
def create_product():
    if current_user.role != 'beneficiary':
        return jsonify({'success': False, 'message': 'Only beneficiaries can create products'})
    
    data = request.get_json()
    
    shipping_cost = float(data['shipping_cost'])
    taxes = float(data['taxes'])
    total_amount = shipping_cost + taxes
    
    required_deposit = total_amount * 0.5
    if current_user.balance < required_deposit:
        return jsonify({'success': False, 'message': f'Insufficient balance. You need ${required_deposit:.2f} for 50% deposit'})
    
    product = Product(
        name=data['name'],
        description=data['description'],
        shipping_cost=shipping_cost,
        taxes=taxes,
        total_amount=total_amount,
        beneficiary_id=current_user.id,
        timeframe=data['timeframe'],
        return_percentage=20.0
    )
    
    current_user.balance -= required_deposit
    db.session.add(product)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Product created successfully! 50% deposit deducted.'})

@app.route('/api/invest', methods=['POST'])
@login_required
def invest():
    if current_user.role != 'investor':
        return jsonify({'success': False, 'message': 'Only investors can invest'})
    
    data = request.get_json()
    product_id = data['product_id']
    
    product = Product.query.get(product_id)
    if not product or product.status != 'active':
        return jsonify({'success': False, 'message': 'Product not available for investment'})
    
    investment_amount = product.total_amount * 0.5
    
    if current_user.balance < investment_amount:
        return jsonify({'success': False, 'message': f'Insufficient balance. You need ${investment_amount:.2f}'})
    
    expected_return = investment_amount * (1 + product.return_percentage / 100)
    investment = Investment(
        investor_id=current_user.id,
        product_id=product_id,
        amount_invested=investment_amount,
        expected_return=expected_return
    )
    
    current_user.balance -= investment_amount
    product.status = 'funded'
    
    transaction = Transaction(
        user_id=current_user.id,
        amount=investment_amount,
        transaction_type='investment'
    )
    
    db.session.add(investment)
    db.session.add(transaction)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'Investment successful! You invested ${investment_amount:.2f} for {product.return_percentage}% return.'
    })

@app.route('/api/deposit', methods=['POST'])
@login_required
def deposit():
    data = request.get_json()
    amount = float(data['amount'])
    
    current_user.balance += amount
    
    transaction = Transaction(
        user_id=current_user.id,
        amount=amount,
        transaction_type='deposit'
    )
    
    db.session.add(transaction)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'Deposit successful! ${amount:.2f} added to your account.',
        'new_balance': current_user.balance
    })

@app.route('/api/withdraw', methods=['POST'])
@login_required
def withdraw():
    data = request.get_json()
    amount = float(data['amount'])
    
    if current_user.balance < amount:
        return jsonify({'success': False, 'message': 'Insufficient balance'})
    
    current_user.balance -= amount
    
    transaction = Transaction(
        user_id=current_user.id,
        amount=amount,
        transaction_type='withdrawal'
    )
    
    db.session.add(transaction)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'Withdrawal successful! ${amount:.2f} withdrawn.',
        'new_balance': current_user.balance
    })
    
    if current_user.balance < amount:
        return jsonify({'success': False, 'message': 'Insufficient balance'})
    
    current_user.balance -= amount
    
    transaction = Transaction(
        user_id=current_user.id,
        amount=amount,
        transaction_type='withdrawal'
    )
    
    db.session.add(transaction)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'Withdrawal successful! ${amount:.2f} withdrawn.',
        'new_balance': current_user.balance
    })

@app.route('/api/transactions')
@login_required
def get_transactions():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.created_at.desc()).limit(10).all()
    transactions_data = []
    for transaction in transactions:
        transactions_data.append({
            'id': transaction.id,
            'amount': transaction.amount,
            'type': transaction.transaction_type,
            'date': transaction.created_at.strftime('%Y-%m-%d %H:%M'),
            'status': transaction.status
        })
    return jsonify(transactions_data)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect('/admin')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
