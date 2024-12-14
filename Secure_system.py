import os
import hashlib
import sqlite3
import jwt
import logging
import datetime
from functools import wraps
from cryptography.fernet import Fernet
from typing import Optional, Dict, List

class SecureInventorySystem:
    def __init__(self, db_path: str = 'inventory.db'):
        self.db_path = db_path
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.jwt_secret = os.urandom(24).hex()
        
        # Setup logging
        logging.basicConfig(
            filename='system_activity.log',
            level=logging.INFO,
            format='%(asctime)s : %(levelname)s : %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Initialize database
        self.setup_database()

    def get_db_connection(self):
        """Create and return a new database connection"""
        return sqlite3.connect(self.db_path, timeout=20)

    def setup_database(self):
        """Initialize SQLite database with required tables"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    mfa_secret TEXT
                )
            ''')
            
            # Products table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY,
                    product_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    price_encrypted TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    last_modified TIMESTAMP,
                    modified_by TEXT
                )
            ''')
            
            # Audit log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY,
                    timestamp TIMESTAMP,
                    user TEXT,
                    action TEXT,
                    details TEXT
                )
            ''')
            
            conn.commit()
            logging.info("Database setup completed successfully")
        except sqlite3.Error as e:
            logging.error(f"Database setup error: {e}")
            raise
        finally:
            conn.close()

    def validate_input(self, **kwargs) -> bool:
        """Validate and sanitize input parameters"""
        for key, value in kwargs.items():
            if key == 'product_id':
                if not value.isalnum():
                    logging.warning(f"Invalid product_id format: {value}")
                    return False
            elif key in ['price', 'quantity']:
                try:
                    float(value)
                except ValueError:
                    logging.warning(f"Invalid {key} format: {value}")
                    return False
            elif key == 'username':
                if not value.isalnum() or len(value) < 3:
                    logging.warning(f"Invalid username format: {value}")
                    return False
        return True

    def hash_password(self, password: str, salt: Optional[str] = None) -> tuple:
        """Secure password hashing with salt"""
        if not salt:
            salt = os.urandom(16).hex()
        hash_obj = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt.encode(),
            100000
        )
        return hash_obj.hex(), salt

    def create_user(self, username: str, password: str, role: str = 'user') -> bool:
        """Create new user with secure password storage"""
        if not self.validate_input(username=username):
            return False
            
        password_hash, salt = self.hash_password(password)
        
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)',
                (username, password_hash, salt, role)
            )
            
            # Log the action in the same transaction
            cursor.execute(
                'INSERT INTO audit_log (timestamp, user, action, details) VALUES (?, ?, ?, ?)',
                (datetime.datetime.now(), username, 'user_created', 'New user account created')
            )
            
            conn.commit()
            logging.info(f"User created successfully: {username}")
            return True
            
        except sqlite3.IntegrityError:
            logging.error(f"Username {username} already exists")
            return False
        except sqlite3.Error as e:
            logging.error(f"Database error during user creation: {e}")
            return False
        finally:
            conn.close()

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and generate JWT token"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT password_hash, salt, role FROM users WHERE username = ?',
                (username,)
            )
            result = cursor.fetchone()
            
            if not result:
                logging.warning(f"Failed login attempt for username: {username}")
                return None
                
            stored_hash, salt, role = result
            computed_hash, _ = self.hash_password(password, salt)
            
            if computed_hash == stored_hash:
                token = jwt.encode(
                    {
                        'username': username,
                        'role': role,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                    },
                    self.jwt_secret,
                    algorithm='HS256'
                )
                
                # Log successful login
                cursor.execute(
                    'INSERT INTO audit_log (timestamp, user, action, details) VALUES (?, ?, ?, ?)',
                    (datetime.datetime.now(), username, 'login', 'Successful login')
                )
                conn.commit()
                logging.info(f"Successful login: {username}")
                return token
                
            logging.warning(f"Invalid password attempt for username: {username}")
            return None
            
        except sqlite3.Error as e:
            logging.error(f"Database error during authentication: {e}")
            return None
        finally:
            conn.close()

    def verify_token(self, token: str) -> Optional[dict]:
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logging.warning("Expired token used")
            return None
        except jwt.InvalidTokenError:
            logging.warning("Invalid token used")
            return None

    def add_product(self, token: str, product_id: str, name: str, price: float, quantity: int) -> bool:
        """Add new product with encrypted sensitive data"""
        user = self.verify_token(token)
        if not user or user['role'] != 'admin':
            logging.warning(f"Unauthorized product addition attempt by {user['username'] if user else 'unknown'}")
            return False
            
        if not self.validate_input(product_id=product_id, price=price, quantity=quantity):
            return False
            
        # Encrypt sensitive data
        encrypted_price = self.cipher_suite.encrypt(str(price).encode())
        
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                '''INSERT INTO products 
                   (product_id, name, price_encrypted, quantity, last_modified, modified_by)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (product_id, name, encrypted_price, quantity, 
                 datetime.datetime.now(), user['username'])
            )
            
            # Log the action
            cursor.execute(
                'INSERT INTO audit_log (timestamp, user, action, details) VALUES (?, ?, ?, ?)',
                (datetime.datetime.now(), user['username'], 'product_added', f"Added product {product_id}")
            )
            
            conn.commit()
            logging.info(f"Product added successfully: {product_id}")
            return True
            
        except sqlite3.IntegrityError:
            logging.error(f"Product ID {product_id} already exists")
            return False
        except sqlite3.Error as e:
            logging.error(f"Database error during product addition: {e}")
            return False
        finally:
            conn.close()

    def update_product_quantity(self, token: str, product_id: str, quantity_change: int) -> bool:
        """Update product quantity with concurrency control"""
        user = self.verify_token(token)
        if not user:
            return False
            
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Start transaction with exclusive lock
            cursor.execute('BEGIN EXCLUSIVE')
            
            cursor.execute(
                'SELECT quantity FROM products WHERE product_id = ?',
                (product_id,)
            )
            result = cursor.fetchone()
            
            if not result:
                conn.rollback()
                return False
                
            current_quantity = result[0]
            new_quantity = current_quantity + quantity_change
            
            if new_quantity < 0:
                conn.rollback()
                return False
                
            cursor.execute(
                '''UPDATE products 
                   SET quantity = ?, last_modified = ?, modified_by = ?
                   WHERE product_id = ?''',
                (new_quantity, datetime.datetime.now(), user['username'], product_id)
            )
            
            # Log the action
            cursor.execute(
                'INSERT INTO audit_log (timestamp, user, action, details) VALUES (?, ?, ?, ?)',
                (datetime.datetime.now(), user['username'], 'quantity_updated', 
                 f"Updated quantity for {product_id} by {quantity_change}")
            )
            
            conn.commit()
            logging.info(f"Product quantity updated: {product_id}, change: {quantity_change}")
            return True
            
        except sqlite3.Error as e:
            logging.error(f"Database error during quantity update: {e}")
            if 'conn' in locals():
                conn.rollback()
            return False
        finally:
            if 'conn' in locals():
                conn.close()

    def get_audit_log(self, token: str, start_date: Optional[datetime.datetime] = None) -> List[dict]:
        """Retrieve audit log entries with access control"""
        user = self.verify_token(token)
        if not user or user['role'] != 'admin':
            logging.warning(f"Unauthorized audit log access attempt by {user['username'] if user else 'unknown'}")
            return []
            
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            if start_date:
                cursor.execute(
                    'SELECT * FROM audit_log WHERE timestamp >= ? ORDER BY timestamp DESC',
                    (start_date,)
                )
            else:
                cursor.execute('SELECT * FROM audit_log ORDER BY timestamp DESC')
                
            logs = [
                {
                    'timestamp': row[1],
                    'user': row[2],
                    'action': row[3],
                    'details': row[4]
                }
                for row in cursor.fetchall()
            ]
            
            logging.info(f"Audit log retrieved by {user['username']}")
            return logs
            
        except sqlite3.Error as e:
            logging.error(f"Database error during audit log retrieval: {e}")
            return []
        finally:
            conn.close()

def main():
    # Initialize the system
    inventory_system = SecureInventorySystem()
    
    while True:
        print("\n=== Secure Inventory Management System ===")
        print("1. Create new user")
        print("2. Login")
        print("3. Exit")
        
        try:
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == "1":
                username = input("Enter username: ")
                password = input("Enter password: ")
                role = input("Enter role (admin/user): ").lower()
                
                if role not in ['admin', 'user']:
                    print("Invalid role! Must be 'admin' or 'user'")
                    continue
                    
                if inventory_system.create_user(username, password, role):
                    print("User created successfully!")
                else:
                    print("Failed to create user. Username might already exist or be invalid.")
                    
            elif choice == "2":
                username = input("Enter username: ")
                password = input("Enter password: ")
                
                token = inventory_system.authenticate(username, password)
                
                if token:
                    print("Login successful!")
                    
                    # Start operations menu loop
                    while True:
                        print("\n=== Inventory Operations ===")
                        print("1. Add new product")
                        print("2. Update product quantity")
                        print("3. View audit log")
                        print("4. Logout")
                        
                        op_choice = input("\nEnter your choice (1-4): ")
                        
                        if op_choice == "1":
                            product_id = input("Enter product ID: ")
                            name = input("Enter product name: ")
                            try:
                                price = float(input("Enter product price: "))
                                quantity = int(input("Enter product quantity: "))
                            except ValueError:
                                print("Invalid price or quantity format!")
                                continue
                                
                            if inventory_system.add_product(token, product_id, name, price, quantity):
                                print("Product added successfully!")
                            else:
                                print("Failed to add product. Check your permissions or product ID.")
                                
                        elif op_choice == "2":
                            product_id = input("Enter product ID: ")
                            try:
                                quantity_change = int(input("Enter quantity change (negative for reduction): "))
                            except ValueError:
                                print("Invalid quantity format!")
                                continue
                                
                            if inventory_system.update_product_quantity(token, product_id, quantity_change):
                                print("Quantity updated successfully!")
                            else:
                                print("Failed to update quantity. Check product ID or resulting quantity.")
                                
                        elif op_choice == "3":
                            logs = inventory_system.get_audit_log(token)
                            if logs:
                                print("\n=== Audit Log ===")
                                for log in logs:
                                    print(f"{log['timestamp']}: {log['user']} - {log['action']} - {log['details']}")
                            else:
                                print("No audit logs available or insufficient permissions.")
                                
                        elif op_choice == "4":
                            print("Logging out...")
                            break
                        else:
                            print("Invalid choice!")
                else:
                    print("Login failed. Please check your credentials.")
                    
            elif choice == "3":
                print("Exiting system...")
                break
            else:
                print("Invalid choice!")
                
        except Exception as e:
            print(f"An error occurred: {e}")
            logging.error(f"System error: {e}")

if __name__ == "__main__":
    main()