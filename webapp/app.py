from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
from config import Config

app = Flask(__name__)

# Database configuration (replace with your actual credentials)
db_config = {
    'host': Config.DB_HOST,
    'user': Config.DB_USER,
    'password': Config.DB_PASSWORD,
    'database': Config.DB_NAME
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# --- Main Menu ---
@app.route('/')
def main_menu():
    return render_template('main_menu.html')

# --- Suppliers CRUD ---

@app.route('/suppliers')
def list_suppliers():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT SupplierID, SupplierName, SupplierContactNo, Address, SupplierEmail, DateCreated FROM Suppliers")
    suppliers = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('suppliers/index.html', suppliers=suppliers)

@app.route('/suppliers/add', methods=['GET', 'POST'])
def add_supplier():
    if request.method == 'POST':
        name = request.form['SupplierName']
        contact_no = request.form['SupplierContactNo']
        address = request.form['Address']
        email = request.form['SupplierEmail']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Suppliers (SupplierName, SupplierContactNo, Address, SupplierEmail) VALUES (%s, %s, %s, %s)",
                       (name, contact_no, address, email))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('list_suppliers'))
    return render_template('suppliers/add.html')

@app.route('/suppliers/edit/<int:id>', methods=['GET', 'POST'])
def edit_supplier(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['SupplierName']
        contact_no = request.form['SupplierContactNo']
        address = request.form['Address']
        email = request.form['SupplierEmail']
        cursor.execute("UPDATE Suppliers SET SupplierName=%s, SupplierContactNo=%s, Address=%s, SupplierEmail=%s WHERE SupplierID=%s",
                       (name, contact_no, address, email, id))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('list_suppliers'))

    cursor.execute("SELECT SupplierID, SupplierName, SupplierContactNo, Address, SupplierEmail, DateCreated FROM Suppliers WHERE SupplierID = %s", (id,))
    supplier = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('suppliers/edit.html', supplier=supplier)

@app.route('/suppliers/delete/<int:id>')
def delete_supplier(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Suppliers WHERE SupplierID = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('list_suppliers'))


# --- Employees CRUD ---

@app.route('/employees')
def list_employees():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT EmpID, EmpName, EmpEmail, Department, JobTitle, Salary, DateCreated FROM Employees")
    employees = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('employees/index.html', employees=employees)

@app.route('/employees/add', methods=['GET', 'POST'])
def add_employee():
    if request.method == 'POST':
        name = request.form['EmpName']
        email = request.form['EmpEmail']
        department = request.form['Department']
        job_title = request.form['JobTitle']
        salary = request.form['Salary']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Employees (EmpName, EmpEmail, Department, JobTitle, Salary) VALUES (%s, %s, %s, %s, %s)",
                       (name, email, department, job_title, salary))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('list_employees'))
    return render_template('employees/add.html')

@app.route('/employees/edit/<int:id>', methods=['GET', 'POST'])
def edit_employee(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['EmpName']
        email = request.form['EmpEmail']
        department = request.form['Department']
        job_title = request.form['JobTitle']
        salary = request.form['Salary']

        cursor.execute("UPDATE Employees SET EmpName=%s, EmpEmail=%s, Department=%s, JobTitle=%s, Salary=%s WHERE EmpID=%s",
                       (name, email, department, job_title, salary, id))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('list_employees'))

    cursor.execute("SELECT EmpID, EmpName, EmpEmail, Department, JobTitle, Salary, DateCreated FROM Employees WHERE EmpID = %s", (id,))
    employee = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('employees/edit.html', employee=employee)

@app.route('/employees/delete/<int:id>')
def delete_employee(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Employees WHERE EmpID = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('list_employees'))


# --- Customers CRUD ---

@app.route('/customers')
def list_customers():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT CustID, CustName, CustEmail, CustContactNo, CustAddress, DateCreated FROM Customers")
    customers = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('customers/index.html', customers=customers)

@app.route('/customers/add', methods=['GET', 'POST'])
def add_customer():
    if request.method == 'POST':
        name = request.form['CustName']
        email = request.form['CustEmail']
        contact_no = request.form['CustContactNo']
        address = request.form['CustAddress']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Customers (CustName, CustEmail, CustContactNo, CustAddress) VALUES (%s, %s, %s, %s)",
                       (name, email, contact_no, address))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('list_customers'))
    return render_template('customers/add.html')

@app.route('/customers/edit/<int:id>', methods=['GET', 'POST'])
def edit_customer(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['CustName']
        email = request.form['CustEmail']
        contact_no = request.form['CustContactNo']
        address = request.form['CustAddress']

        cursor.execute("UPDATE Customers SET CustName=%s, CustEmail=%s, CustContactNo=%s, CustAddress=%s WHERE CustID=%s",
                       (name, email, contact_no, address, id))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('list_customers'))

    cursor.execute("SELECT CustID, CustName, CustEmail, CustContactNo, CustAddress, DateCreated FROM Customers WHERE CustID = %s", (id,))
    customer = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('customers/edit.html', customer=customer)

@app.route('/customers/delete/<int:id>')
def delete_customer(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Customers WHERE CustID = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('list_customers'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)