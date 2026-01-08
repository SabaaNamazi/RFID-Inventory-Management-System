from datetime import datetime, timedelta
from flask import Flask, Response, jsonify, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import schedule
import time
import io
import csv
import pandas as pd
import smtplib
import requests, time, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import os


app = Flask(__name__)
app.secret_key = 'wverihdfuvuwi2482'


def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="rfid_inventory"
    )

@app.route('/scan', methods=['GET', 'POST'])
def scan_rfid():
    if request.method == 'POST':
        data = request.json
    else:
        data = request.args

    rfid_tag = data.get('rfid_tag')
    quantity = int(data.get('quantity', 1))
    action = data.get('action')

   
    if not rfid_tag or action != 'in':
        return jsonify({'status': 'error', 'message': 'Invalid input or only "in" action allowed'}), 400

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

   
    cursor.execute("SELECT * FROM products WHERE rfid_tag = %s", (rfid_tag,))
    product = cursor.fetchone()
    if not product:
        return jsonify({'status': 'error', 'message': 'RFID not found'}), 404

  
    new_stock = product['stock'] + quantity
    cursor.execute("UPDATE products SET stock = %s WHERE rfid_tag = %s", (new_stock, rfid_tag))

    
    cursor.execute(
        "INSERT INTO stock_log (rfid_tag, quantity, action) VALUES (%s, %s, %s)",
        (rfid_tag, quantity, action)
    )

    db.commit()
    cursor.close()
    db.close()

    return jsonify({'status': 'success', 'new_stock': new_stock}), 200




@app.route('/')
def home():
    return render_template('home.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        number = request.form['number']
        password = request.form['password']
        role = 'user'
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (name, email, number, password, role) VALUES (%s, %s, %s, %s, %s)',
                (name, email, number, hashed_password, role)
            )
            conn.commit()
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Email already exists.', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['email'] = user['email']
            session['role'] = user['role']
            session['user_id'] = user['id']
            session['name'] = user['name']
            flash('Login successful!', 'success')
            # print("Logged in user ID:", session['user_id'])
            # print("User role from DB:", user['role'])

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_products'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')

@app.route('/products')
def user_products():
    if session.get('role') != 'user':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login')) 

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    cursor.close()
    db.close()
    return render_template('user_products.html', products=products)

@app.route('/buy/<int:product_id>', methods=['POST'])
def buy_product(product_id):
    if session.get('role') != 'user':
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    quantity = int(request.form.get('quantity', 1))

    db = get_db_connection()
    cursor = db.cursor()

    # Check current stock
    cursor.execute("SELECT stock FROM products WHERE id = %s", (product_id,))
    result = cursor.fetchone()

    if result and result[0] >= quantity:
        # Reduce stock
        cursor.execute("UPDATE products SET stock = stock - %s WHERE id = %s", (quantity, product_id))

        # Insert into orders
        cursor.execute("""
            INSERT INTO orders (user_id, product_id, quantity, order_date)
            VALUES (%s, %s, %s, NOW())
        """, (user_id, product_id, quantity))

        db.commit()
        flash(f"Ordered {quantity} item(s) successfully!", "success")
    else:
        flash("Not enough stock available!", "danger")

    cursor.close()
    db.close()
    return redirect(url_for('user_products'))
@app.route('/profile')
def profile():
    if session.get('role') != 'user':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id')

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Get user info
    cursor.execute("SELECT name, email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    # Get user's orders with product name
    cursor.execute("""
        SELECT o.quantity, o.order_date, p.name AS product_name
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.user_id = %s
        ORDER BY o.order_date DESC
    """, (user_id,))
    orders = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('profile.html', user=user, orders=orders)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


################################### Admin Dashboard ###################

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Get admin info
    cursor.execute("SELECT * FROM users WHERE email = %s", (session['email'],))
    admin = cursor.fetchone()

    # Total products
    cursor.execute("SELECT COUNT(*) AS total_products FROM products")
    total_products = cursor.fetchone()['total_products']

    # Low stock products (stock < 10)
    cursor.execute("SELECT COUNT(*) AS low_stock FROM products WHERE stock >= 1 AND stock <= 5")
    low_stock = cursor.fetchone()['low_stock']

    
    cursor.execute("SELECT COUNT(*) AS fast_moving FROM products WHERE stock BETWEEN 10 AND 50")
    fast_moving = cursor.fetchone()['fast_moving']

    # Dead stock (stock = 0)
    cursor.execute("SELECT COUNT(*) AS dead_stock FROM products WHERE DATEDIFF(CURDATE(), updated_at) > 30")
    dead_stock = cursor.fetchone()['dead_stock']


    # Total orders
    cursor.execute("SELECT COUNT(*) AS total_orders FROM orders")
    total_orders = cursor.fetchone()['total_orders']

    # Top ordered products (top 5)
    cursor.execute("""
        SELECT p.name, SUM(o.quantity) AS total_ordered
        FROM orders o
        JOIN products p ON o.product_id = p.id
        GROUP BY o.product_id
        ORDER BY total_ordered DESC
        LIMIT 5
    """)
    top_ordered = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('admin_dashboard.html',
                           admin=admin,
                           total_products=total_products,
                           low_stock=low_stock,
                           fast_moving=fast_moving,
                           dead_stock=dead_stock,
                           total_orders=total_orders,
                           top_ordered=top_ordered)

@app.route('/admin/add-product', methods=['GET', 'POST'])
def add_product():
    if request.method == 'POST':
        rfid_tag = request.form['rfid_tag']
        name = request.form['name']
        category = request.form['category']
        stock = request.form['stock']

        db = get_db_connection()
        cursor = db.cursor()

        query = """
        INSERT INTO products (rfid_tag, name, category, stock, created_at)
        VALUES (%s, %s, %s, %s, %s)
        """
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(query, (rfid_tag, name, category, stock, now))
        db.commit()

        cursor.close()
        db.close()

        flash('Product added successfully!', 'success')
        return redirect(url_for('add_product'))

    return render_template('add_product.html')


@app.route('/admin/product-list', methods=['GET'])
def product_list():
    if session.get('role') != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))
    
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Admin info
    cursor.execute("SELECT * FROM users WHERE email = %s", (session['email'],))
    admin = cursor.fetchone()

    # Fetch all products
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()

    db.close()
    
    return render_template('product_list.html', products=products, admin=admin)


@app.route('/admin/user-list', methods=['GET'])
def user_list():
    if session.get('role') != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))
    
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    
    cursor.execute("SELECT * FROM users WHERE email = %s", (session['email'],))
    admin = cursor.fetchone()

    # Fetch all users
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    db.close()
    
    return render_template('users_list.html', users=users, admin=admin)

@app.route('/admin/edit-product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if session.get('role') != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

   
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found", "danger")
        return redirect(url_for('product_list'))

   
    # ALL_RFID_TAGS = [
    #     "3E00BD6442A5", "3E00BD61F416", "3E00BD61E80A", "3E00BD61FB19",
    #     "3E00BD6206E7", "3E00BD61BB59", "3E00BCC899D3", "3E00BD61FE1C"
    # ]

    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        stock = request.form['stock']
        rfid_tag = request.form['rfid_tag']

        
        if rfid_tag:
            cursor.execute("SELECT id FROM products WHERE rfid_tag = %s AND id != %s", (rfid_tag, product_id))
            if cursor.fetchone():
                flash("RFID tag already assigned to another product", "danger")
                return redirect(url_for('edit_product', product_id=product_id))

        cursor.execute("""
            UPDATE products 
            SET name=%s, category=%s, stock=%s, rfid_tag=%s 
            WHERE id=%s
        """, (name, category, stock, rfid_tag if rfid_tag else None, product_id))

        db.commit()
        cursor.close()
        db.close()
        flash("Product updated successfully", "success")
        return redirect(url_for('product_list'))

    cursor.close()
    db.close()
    return render_template('edit_product.html', product=product)



    
   


# @app.route('/admin/delete-product/<int:product_id>', methods=['GET'])
# def delete_product(product_id):
#     if session.get('role') != 'admin':
#         flash("Unauthorized access", "danger")
#         return redirect(url_for('login'))

#     db = get_db_connection()
#     cursor = db.cursor()
#     cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
#     db.commit()
#     cursor.close()
#     db.close()

#     flash("Product deleted", "success")
#     return redirect(url_for('product_list'))

@app.route('/admin/delete-product/<int:product_id>', methods=['GET'])
def delete_product(product_id):
    if session.get('role') != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("UPDATE products SET is_deleted = 1 WHERE id = %s", (product_id,))
    db.commit()
    cursor.close()
    db.close()

    flash("Product marked as deleted", "success")
    return redirect(url_for('product_list'))


@app.route('/admin/inventory', methods=['GET', 'POST'])
def inventory():
    if session.get('role') != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    if request.method == 'POST':
        product_id = request.form['product_id']
        action = request.form['action']

        if action == "in":
            cursor.execute("UPDATE products SET stock = stock + 1 WHERE id = %s", (product_id,))
        elif action == "out":
            cursor.execute("UPDATE products SET stock = GREATEST(stock - 1, 0) WHERE id = %s", (product_id,))
        elif action == "set_zero":
            cursor.execute("UPDATE products SET stock = 0 WHERE id = %s", (product_id,))
        
        db.commit()

    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()

    return render_template("inventory.html", products=products)

@app.route('/admin/analytics')
def analytics_dashboard():
    if session.get('role') != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # A. Daily Sales Trend (based on products created in last 30 days)
    cursor.execute("""
    SELECT 
        DATE(order_date) AS date, 
        SUM(quantity) AS count
    FROM orders
    WHERE order_date >= CURDATE() - INTERVAL 30 DAY
    GROUP BY DATE(order_date)
    ORDER BY date
""")
    daily_sales = cursor.fetchall()

   
    for d in daily_sales:
        d['date'] = d['date'].strftime('%Y-%m-%d')

    # B. Top Selling Products (based on total quantity sold from orders)
    cursor.execute("""
        SELECT p.name, SUM(o.quantity) AS value
        FROM orders o
        JOIN products p ON o.product_id = p.id
        GROUP BY p.id, p.name
        ORDER BY value DESC
        LIMIT 5
    """)
    top_products = cursor.fetchall()

    # C. Dead Stock (not updated in past 30 days)
    cursor.execute("""
        SELECT * FROM products
        WHERE DATEDIFF(CURDATE(), updated_at) > 30
    """)
    dead_stock = cursor.fetchall()

    # D. Product Movement Tagging (based on current stock levels)
    cursor.execute("SELECT name, stock FROM products")
    all_products = cursor.fetchall()

    fast = slow = non = 0
    for p in all_products:
        if p['stock'] <= 2:
            fast += 1
        elif 3 <= p['stock'] <= 10:
            slow += 1
        else:
            non += 1

    movement = {
        'fast': fast,
        'slow': slow,
        'non': non
    }

    return render_template('analytics.html',
                           daily_sales=daily_sales,
                           top_products=top_products,
                           dead_stock=dead_stock,
                           movement=movement)


@app.route('/admin/combo-analysis')
def combo_analysis():
    if session.get('role') != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))
    
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Find products bought together in the same order
    cursor.execute("""
    SELECT 
        p1.name AS product_A,
        p2.name AS product_B,
        COUNT(*) AS times_bought_together
    FROM orders o1
    JOIN orders o2 
        ON o1.user_id = o2.user_id 
        AND DATE(o1.order_date) = DATE(o2.order_date)
        AND o1.product_id < o2.product_id
    JOIN products p1 ON o1.product_id = p1.id
    JOIN products p2 ON o2.product_id = p2.id
    GROUP BY p1.name, p2.name
    ORDER BY times_bought_together DESC
    LIMIT 20
""")

    combos = cursor.fetchall()

    cursor.close()
    db.close()
    return render_template("combo_analysis.html", combos=combos)

@app.route('/admin/adduser', methods=['GET', 'POST'])
def admin_create():
    if session.get('role') != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        number = request.form['number']
        password = request.form['password']
        role = request.form['role']

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (name, email, number, password, role) VALUES (%s, %s, %s, %s, %s)',
                (name, email, number, hashed_password, role)
            )
            conn.commit()
            flash('User created successfully.', 'success')
            return redirect(url_for('admin_create')) 
        except mysql.connector.IntegrityError:
            flash('Email already exists.', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('admin_adduser.html')


@app.route('/admin/stock-alerts')
def stock_alerts():
    if session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Low stock (<5)
    cursor.execute("SELECT name, category, stock FROM products WHERE stock < 5")
    low_stock_alerts = cursor.fetchall()

    # Overstock (>100 and no sales in last 30 days)
    cursor.execute("""
        SELECT name, category, stock FROM products
        WHERE stock > 100 AND id NOT IN (
            SELECT DISTINCT product_id FROM orders
            WHERE order_date >= CURDATE() - INTERVAL 30 DAY
        )
    """)
    over_stock_alerts = cursor.fetchall()

 
    alert_products = low_stock_alerts + over_stock_alerts

    
    cursor.close()
    db.close()

    return render_template('stock_alerts.html',
                           alert_products=alert_products,
                           low_stock_count=len(low_stock_alerts),
                           over_stock_count=len(over_stock_alerts))



def send_email(data):
    sender_email = "saumyasrivip@gmail.com"
    app_password = "ccix mjty pajc otjd"
    receiver_email = "sabaanamazi2004@gmail.com"

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "🚨  Threshold stock alert"

    html = """
    <html><body>
    <h2 style="text-align:center; color:#d9534f;">📦 Threshold Stock Alerts Report</h2>
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse; width:100%;">
        <tr style="background-color:#f8d7da;">
            <th>Product Name</th>
            <th>Category</th>
            <th>Stock</th>
        </tr>
    """

    for item in data:
        html += f"""
        <tr>
            <td>{item['name']}</td>
            <td>{item['category']}</td>
            <td>{item['stock']}</td>
        </tr>
        """
    html += "</table></body></html>"
    message.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Stock alert Email senting successfully!")
    except Exception as e:
        print(f" Email error: {e}")

def auto_stock_alert_job():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT name, category, stock FROM products WHERE stock < 5")
    low = cursor.fetchall()

    cursor.execute("""
        SELECT name, category, stock FROM products
        WHERE stock > 100 AND id NOT IN (
            SELECT DISTINCT product_id FROM orders
            WHERE order_date >= CURDATE() - INTERVAL 30 DAY
        )
    """)
 
    over = cursor.fetchall()
    alert_products = low + over

    if alert_products:
        send_email(alert_products)

    cursor.close()
    db.close()


schedule.every(3600).seconds.do(auto_stock_alert_job)  # Runs every 500 seconds



def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

@app.route('/admin/reports')
def reports():
    if session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    return render_template('reports.html')

@app.route('/admin/download-report')
def download_report():
    report_type = request.args.get('report_type')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    if report_type == 'inventory':
        cursor.execute("SELECT id, name, category, stock, created_at, updated_at FROM products")
        rows = cursor.fetchall()
        headers = ['ID', 'Name', 'Category', 'Stock', 'Created At', 'Updated At']

    elif report_type == 'sales':
        query = """
            SELECT o.id, p.name, p.category, o.quantity, o.order_date
            FROM orders o JOIN products p ON o.product_id = p.id
            WHERE 1
        """
        params = []
        if from_date:
            query += " AND o.order_date >= %s"
            params.append(from_date)
        if to_date:
            to_date_dt = datetime.strptime(to_date, "%Y-%m-%d") + timedelta(days=1)
            query += " AND o.order_date < %s"
            params.append(to_date_dt.strftime("%Y-%m-%d"))


        cursor.execute(query, params)
        rows = cursor.fetchall()
        headers = ['Order ID', 'Product Name', 'Category', 'Quantity', 'Order Date']

    elif report_type == 'deadstock':
        query = """
            SELECT p.id, p.name, p.category, p.stock
            FROM products p
            WHERE p.stock > 0
              AND p.id NOT IN (
                  SELECT DISTINCT product_id FROM orders
                  WHERE order_date >= CURDATE() - INTERVAL 30 DAY
              )
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        headers = ['Product ID', 'Name', 'Category', 'Stock']

    else:
        return "Invalid report type"

   
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row.values())

    output.seek(0)
    cursor.close()
    db.close()

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment; filename={report_type}_report.csv"}
    )

@app.route('/admin/ml-based', methods=['GET', 'POST'])
def ml_based():
    if session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            csv_path = 'product_data.csv'
            df = pd.read_csv(csv_path)

            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="rfid_inventory"
            )
            cursor = conn.cursor()

            for _, row in df.iterrows():
                cursor.execute("""
                    INSERT INTO products (id, rfid_tag, name, category, stock, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        rfid_tag = VALUES(rfid_tag),
                        name = VALUES(name),
                        category = VALUES(category),
                        stock = VALUES(stock),
                        created_at = VALUES(created_at),
                        updated_at = VALUES(updated_at)
                """, (
                    int(row['id']),
                    row['rfid_tag'],
                    row['name'],
                    row['category'],
                    int(row['stock']),
                    row['created_at'],
                    row['updated_at']
                ))

            conn.commit()
            conn.close()
            flash("Data inserted/updated successfully from CSV.")
        except Exception as e:
            flash(f"Error occurred: {str(e)}")

    return render_template('ml_reload.html')

@app.route('/admin/settings', methods=['GET', 'POST'])
def settings():
    if session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_pwd = request.form['currentPassword']
        new_pwd = request.form['newPassword']
        confirm_pwd = request.form['confirmPassword']

        if new_pwd != confirm_pwd:
            flash("New passwords do not match.", "danger")
            return redirect(url_for('settings'))

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT password FROM users WHERE email = %s", (session['email'],))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], current_pwd):
            new_hashed_pwd = generate_password_hash(new_pwd)
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (new_hashed_pwd, session['email']))
            db.commit()
            db.close()
            flash("Password updated successfully.", "success")
        else:
            flash("Current password is incorrect.", "danger")

    return render_template('settings.html')


if __name__ == '__main__':
    #print("🚀 Starting stock alert scheduler in background...")
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    app.run(host='0.0.0.0', port=5000)


