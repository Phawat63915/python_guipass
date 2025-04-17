# -*- coding: utf-8 -*-

import customtkinter as ctk
from tkinter import messagebox, simpledialog, Toplevel, ttk, Listbox, Scrollbar, Frame, END, SINGLE, W, EW, NS, NSEW, VERTICAL, HORIZONTAL
import sqlite3
import os
import base64
import pyperclip  # pip install pyperclip
import pyotp      # pip install pyotp
import secrets    # For generating secure random bytes & passwords
import string
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from typing import Optional, Tuple, List, Dict, Any, Union
# Optional: for password strength checking (install zxcvbn-python)
try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False
    print("Warning: zxcvbn library not found. Password strength check disabled. Install with: pip install zxcvbn-python")


# --- Constants ---
APP_NAME = "Advanced Secure Vault"
DB_FILENAME = "advanced_vault.db"
MASTER_SALT_FILENAME = "adv_vault.salt"
KDF_ITERATIONS = 600000
CLIPBOARD_CLEAR_DELAY_MS = 30000
PASSWORD_GENERATOR_DEFAULT_LENGTH = 16
TOTP_DISPLAY_DURATION_MS = 30000 # How long the TOTP code is shown

# Character sets for password generator
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""


# --- Security Utilities ---

class SecurityManager:
    """Handles encryption, decryption, key derivation, salt management, TOTP, password generation, and strength checking."""

    @staticmethod
    def generate_salt(size: int = 16) -> bytes:
        return secrets.token_bytes(size)

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        if not password or not salt:
            raise ValueError("Password and salt cannot be empty for key derivation.")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def encrypt_data(data: Union[str, bytes], key: bytes) -> Tuple[bytes, bytes]:
        if not isinstance(data, (str, bytes)):
            raise TypeError("Data to encrypt must be a string or bytes.")
        if not key or len(key) != 32:
            raise ValueError("A valid 32-byte encryption key is required.")

        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
        return nonce, ciphertext

    @staticmethod
    def decrypt_data(nonce: Optional[bytes], ciphertext: Optional[bytes], key: bytes) -> Optional[str]:
        if not key or len(key) != 32:
            print("Decryption Error: Invalid key provided.")
            return None
        if not nonce or not ciphertext:
            # If nonce/ciphertext is None (e.g., optional field not set), return None directly
            return None

        aesgcm = AESGCM(key)
        try:
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            # Attempt decoding, handle potential errors if original wasn't UTF-8
            try:
                 return decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                 print("Warning: Decrypted data was not valid UTF-8. Returning raw bytes representation.")
                 # Fallback: return as base64 or hex if needed, or handle specific binary fields
                 return base64.b64encode(decrypted_bytes).decode('ascii') # Example fallback
        except InvalidTag:
            print("Decryption Error: InvalidTag - Data integrity check failed (wrong key or tampered data).")
            return None
        except Exception as e:
            print(f"Decryption Error: An unexpected error occurred - {e}")
            return None

    @staticmethod
    def generate_totp_code(secret: str) -> Optional[str]:
        """Generates the current Time-based One-Time Password (TOTP)."""
        if not secret:
            return None
        try:
            # pyotp expects base32 encoded secret by default
            # We assume the stored secret is already base32 or needs padding.
            # Basic padding check:
            secret = secret.strip().upper()
            padding = "=" * (-len(secret) % 8)
            totp = pyotp.TOTP(secret + padding)
            return totp.now()
        except Exception as e:
            print(f"Error generating TOTP: {e}")
            return None # Indicate failure

    @staticmethod
    def generate_password(length: int = 16, use_lowercase: bool = True, use_uppercase: bool = True, use_digits: bool = True, use_symbols: bool = True) -> Optional[str]:
        """Generates a secure random password based on selected character sets."""
        char_pool = ""
        if use_lowercase: char_pool += LOWERCASE
        if use_uppercase: char_pool += UPPERCASE
        if use_digits: char_pool += DIGITS
        if use_symbols: char_pool += SYMBOLS

        if not char_pool:
             messagebox.showwarning("Password Generation", "At least one character set must be selected.")
             return None
        if length <= 0:
             messagebox.showwarning("Password Generation", "Password length must be positive.")
             return None

        # Ensure at least one character from each selected mandatory set if possible (simplistic approach)
        password_chars = []
        required_count = 0
        if use_lowercase:
            password_chars.append(secrets.choice(LOWERCASE))
            required_count += 1
        if use_uppercase:
            password_chars.append(secrets.choice(UPPERCASE))
            required_count += 1
        if use_digits:
            password_chars.append(secrets.choice(DIGITS))
            required_count += 1
        if use_symbols:
            password_chars.append(secrets.choice(SYMBOLS))
            required_count += 1

        # Fill remaining length
        remaining_length = max(0, length - required_count)
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(char_pool))

        # Shuffle to avoid predictable start
        secrets.SystemRandom().shuffle(password_chars)

        return "".join(password_chars)

    @staticmethod
    def check_password_strength(password: str) -> Dict[str, Any]:
        """Checks password strength using zxcvbn library if available."""
        if not ZXCVBN_AVAILABLE or not password:
            return {"score": -1, "feedback": None, "crack_time_display": "N/A"} # Indicate N/A

        try:
            results = zxcvbn(password)
            # Simplify feedback for basic display
            feedback = []
            if results['feedback']['warning']:
                 feedback.append(f"Warning: {results['feedback']['warning']}")
            feedback.extend(results['feedback']['suggestions'])

            return {
                "score": results['score'], # 0-4 (0=worst, 4=best)
                "feedback": "\n".join(feedback) if feedback else "Looks good.",
                "crack_time_display": results['crack_times_display']['offline_slow_hashing_1e4_per_second'] # Example crack time
            }
        except Exception as e:
            print(f"Error checking password strength: {e}")
            return {"score": -1, "feedback": "Error during check.", "crack_time_display": "Error"}


# --- Database Management ---

class DatabaseManager:
    """Handles all interactions with the SQLite database, including new tables."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._cursor: Optional[sqlite3.Cursor] = None

    def connect(self) -> None:
        try:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON;") # Enable foreign key constraints
            self._cursor = self._conn.cursor()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to connect to database: {e}")
            self._conn = self._cursor = None
            raise

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = self._cursor = None

    def _ensure_connected(self) -> None:
        if not self._conn or not self._cursor:
             raise sqlite3.DatabaseError("Database is not connected.")

    def initialize_schema(self) -> None:
        self._ensure_connected()
        try:
            # Categories Table
            self._cursor.execute('''
                CREATE TABLE IF NOT EXISTS categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL COLLATE NOCASE
                )
            ''')

            # Entries Table
            self._cursor.execute('''
                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category_id INTEGER,
                    service_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    encrypted_password BLOB NOT NULL,
                    totp_secret_nonce BLOB,
                    encrypted_totp_secret BLOB,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL
                )
            ''')
             # Optional: Unique constraint on service+username per category? Or globally?
             # CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_entry ON entries (category_id, service_name, username);

            # Recovery Contacts Table
            self._cursor.execute('''
                CREATE TABLE IF NOT EXISTS recovery_contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id INTEGER NOT NULL,
                    contact_type TEXT NOT NULL CHECK(contact_type IN ('email', 'phone')),
                    value TEXT NOT NULL,
                    FOREIGN KEY(entry_id) REFERENCES entries(id) ON DELETE CASCADE
                )
            ''')

            # Custom Fields Table
            self._cursor.execute('''
                CREATE TABLE IF NOT EXISTS custom_fields (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id INTEGER NOT NULL,
                    field_name TEXT NOT NULL,
                    field_value_nonce BLOB NOT NULL, -- Nonce always needed for encryption
                    encrypted_field_value BLOB NOT NULL,
                    is_secret INTEGER NOT NULL DEFAULT 0 CHECK(is_secret IN (0, 1)), -- 1 for secret, 0 for visible
                    FOREIGN KEY(entry_id) REFERENCES entries(id) ON DELETE CASCADE
                )
            ''')

            # Indexes for faster lookups
            self._cursor.execute('CREATE INDEX IF NOT EXISTS idx_entry_category ON entries (category_id)')
            self._cursor.execute('CREATE INDEX IF NOT EXISTS idx_entry_service ON entries (service_name)')
            self._cursor.execute('CREATE INDEX IF NOT EXISTS idx_contacts_entry ON recovery_contacts (entry_id)')
            self._cursor.execute('CREATE INDEX IF NOT EXISTS idx_custom_fields_entry ON custom_fields (entry_id)')

            # Trigger for updated_at on entries table
            self._cursor.execute('''
                CREATE TRIGGER IF NOT EXISTS update_entry_timestamp_trigger
                AFTER UPDATE ON entries FOR EACH ROW
                BEGIN
                    UPDATE entries SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
                END;
            ''')

            self._conn.commit()
        except sqlite3.Error as e:
            messagebox.showerror("Database Schema Error", f"Failed to initialize/update database schema: {e}")
            raise

    # --- Category Methods ---
    def add_category(self, name: str) -> Optional[int]:
        self._ensure_connected()
        try:
            self._cursor.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            self._conn.commit()
            return self._cursor.lastrowid
        except sqlite3.IntegrityError:
            messagebox.showwarning("Duplicate Category", f"Category '{name}' already exists.", parent=ctk.CTk()) # Needs parent context
            return None
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to add category: {e}", parent=ctk.CTk())
            self._conn.rollback()
            return None

    def get_all_categories(self) -> List[Dict[str, Any]]:
        self._ensure_connected()
        try:
            self._cursor.execute("SELECT id, name FROM categories ORDER BY name")
            return [dict(row) for row in self._cursor.fetchall()]
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to retrieve categories: {e}", parent=ctk.CTk())
            return []

    def delete_category(self, category_id: int) -> bool:
         self._ensure_connected()
         try:
             # Entries using this category will have category_id set to NULL due to ON DELETE SET NULL
             self._cursor.execute("DELETE FROM categories WHERE id=?", (category_id,))
             self._conn.commit()
             return self._cursor.rowcount > 0
         except sqlite3.Error as e:
             messagebox.showerror("Database Error", f"Failed to delete category: {e}", parent=ctk.CTk())
             self._conn.rollback()
             return False

    # --- Entry Methods (Modified) ---
    def add_entry(self, data: Dict[str, Any]) -> Optional[int]:
        """Adds a new entry with associated data."""
        self._ensure_connected()
        try:
            with self._conn: # Use context manager for automatic commit/rollback
                # Insert base entry
                self._cursor.execute(
                    """INSERT INTO entries (category_id, service_name, username, nonce, encrypted_password,
                                          totp_secret_nonce, encrypted_totp_secret, notes)
                       VALUES (:category_id, :service_name, :username, :nonce, :encrypted_password,
                               :totp_secret_nonce, :encrypted_totp_secret, :notes)""",
                    data # Pass dict directly
                )
                entry_id = self._cursor.lastrowid
                if not entry_id:
                     raise sqlite3.DatabaseError("Failed to get last inserted entry ID.")

                # Insert recovery contacts
                if data.get('recovery_contacts'):
                    contacts_data = [(entry_id, c['type'], c['value']) for c in data['recovery_contacts']]
                    self._cursor.executemany(
                        "INSERT INTO recovery_contacts (entry_id, contact_type, value) VALUES (?, ?, ?)",
                        contacts_data
                    )

                # Insert custom fields
                if data.get('custom_fields'):
                    fields_data = [(entry_id, f['name'], f['nonce'], f['encrypted_value'], f['is_secret'])
                                   for f in data['custom_fields']]
                    self._cursor.executemany(
                        """INSERT INTO custom_fields (entry_id, field_name, field_value_nonce,
                                                  encrypted_field_value, is_secret) VALUES (?, ?, ?, ?, ?)""",
                        fields_data
                    )
            return entry_id
        except sqlite3.IntegrityError as e:
             # More specific error needed if unique constraint is added
             messagebox.showwarning("Data Error", f"Failed to add entry due to data constraint: {e}", parent=ctk.CTk())
             return None
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to add entry and associated data: {e}", parent=ctk.CTk())
            # Rollback is handled by 'with self._conn' on exception
            return None

    def update_entry(self, entry_id: int, data: Dict[str, Any]) -> bool:
        """Updates an entry and its associated data."""
        self._ensure_connected()
        try:
            with self._conn:
                # Update base entry
                self._cursor.execute(
                    """UPDATE entries SET
                           category_id=:category_id, service_name=:service_name, username=:username,
                           nonce=:nonce, encrypted_password=:encrypted_password,
                           totp_secret_nonce=:totp_secret_nonce, encrypted_totp_secret=:encrypted_totp_secret,
                           notes=:notes
                       WHERE id=:id""",
                    data # Pass dict, ensure 'id' key is present
                )

                # Update associated data (delete old, insert new - simpler than diffing)
                # Recovery Contacts
                self._cursor.execute("DELETE FROM recovery_contacts WHERE entry_id=?", (entry_id,))
                if data.get('recovery_contacts'):
                    contacts_data = [(entry_id, c['type'], c['value']) for c in data['recovery_contacts']]
                    self._cursor.executemany(
                        "INSERT INTO recovery_contacts (entry_id, contact_type, value) VALUES (?, ?, ?)",
                        contacts_data
                    )

                # Custom Fields
                self._cursor.execute("DELETE FROM custom_fields WHERE entry_id=?", (entry_id,))
                if data.get('custom_fields'):
                     fields_data = [(entry_id, f['name'], f['nonce'], f['encrypted_value'], f['is_secret'])
                                   for f in data['custom_fields']]
                     self._cursor.executemany(
                        """INSERT INTO custom_fields (entry_id, field_name, field_value_nonce,
                                                  encrypted_field_value, is_secret) VALUES (?, ?, ?, ?, ?)""",
                        fields_data
                    )
            return self._cursor.rowcount > 0 # Check if entry row was updated
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to update entry: {e}", parent=ctk.CTk())
            return False

    def delete_entry(self, entry_id: int) -> bool:
        self._ensure_connected()
        try:
            # CASCADE delete takes care of recovery_contacts and custom_fields
            self._cursor.execute("DELETE FROM entries WHERE id=?", (entry_id,))
            self._conn.commit()
            return self._cursor.rowcount > 0
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to delete entry: {e}", parent=ctk.CTk())
            self._conn.rollback()
            return False

    def get_entries_summary(self, category_id: Optional[int] = None, search_term: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves summaries, optionally filtered by category and search term."""
        self._ensure_connected()
        try:
            query = """
                SELECT e.id, e.service_name, e.username, c.name as category_name
                FROM entries e
                LEFT JOIN categories c ON e.category_id = c.id
            """
            params = []
            conditions = []

            if category_id is not None:
                conditions.append("e.category_id = ?")
                params.append(category_id)
            if search_term:
                # Search across service, username, notes, category name
                conditions.append("(e.service_name LIKE ? OR e.username LIKE ? OR e.notes LIKE ? OR c.name LIKE ?)")
                term = f"%{search_term}%"
                params.extend([term, term, term, term])

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY c.name, e.service_name, e.username"

            self._cursor.execute(query, params)
            return [dict(row) for row in self._cursor.fetchall()]
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to retrieve entry summaries: {e}", parent=ctk.CTk())
            return []

    def get_entry_full_details(self, entry_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves all details for an entry, including associated data."""
        self._ensure_connected()
        details = {}
        try:
            # Get base entry
            self._cursor.execute("SELECT * FROM entries WHERE id=?", (entry_id,))
            entry_row = self._cursor.fetchone()
            if not entry_row: return None
            details = dict(entry_row)

            # Get recovery contacts
            self._cursor.execute("SELECT contact_type, value FROM recovery_contacts WHERE entry_id=?", (entry_id,))
            details['recovery_contacts'] = [dict(row) for row in self._cursor.fetchall()]

            # Get custom fields
            self._cursor.execute("SELECT field_name, field_value_nonce, encrypted_field_value, is_secret FROM custom_fields WHERE entry_id=?", (entry_id,))
            details['custom_fields'] = [dict(row) for row in self._cursor.fetchall()]

            return details
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to retrieve full entry details: {e}", parent=ctk.CTk())
            return None


# --- GUI Components ---

class PasswordGeneratorDialog(ctk.CTkToplevel):
    """Dialog for generating secure passwords."""
    def __init__(self, parent):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.title("Password Generator")
        self.geometry("400x350")
        self.parent = parent
        self.generated_password: Optional[str] = None

        self._create_widgets()
        self._update_password() # Generate initial password

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.wait_window(self)

    def _create_widgets(self):
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        # Length
        len_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        len_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(len_frame, text="Length:").pack(side="left", padx=(0, 10))
        self.length_slider_var = ctk.IntVar(value=PASSWORD_GENERATOR_DEFAULT_LENGTH)
        self.length_slider = ctk.CTkSlider(len_frame, from_=8, to=64, number_of_steps=56, variable=self.length_slider_var, command=lambda v: self._update_length_label(int(v)))
        self.length_slider.pack(side="left", fill="x", expand=True, padx=5)
        self.length_label = ctk.CTkLabel(len_frame, text=str(PASSWORD_GENERATOR_DEFAULT_LENGTH), width=30)
        self.length_label.pack(side="left")

        # Character Sets
        sets_frame = ctk.CTkFrame(main_frame)
        sets_frame.pack(fill="x", pady=10)
        sets_frame.grid_columnconfigure((0,1), weight=1)

        self.use_lower_var = ctk.BooleanVar(value=True)
        self.use_upper_var = ctk.BooleanVar(value=True)
        self.use_digits_var = ctk.BooleanVar(value=True)
        self.use_symbols_var = ctk.BooleanVar(value=True)

        ctk.CTkCheckBox(sets_frame, text="Lowercase (a-z)", variable=self.use_lower_var, command=self._update_password).grid(row=0, column=0, sticky="w", padx=10, pady=2)
        ctk.CTkCheckBox(sets_frame, text="Uppercase (A-Z)", variable=self.use_upper_var, command=self._update_password).grid(row=0, column=1, sticky="w", padx=10, pady=2)
        ctk.CTkCheckBox(sets_frame, text="Digits (0-9)", variable=self.use_digits_var, command=self._update_password).grid(row=1, column=0, sticky="w", padx=10, pady=2)
        ctk.CTkCheckBox(sets_frame, text="Symbols (!@#...)", variable=self.use_symbols_var, command=self._update_password).grid(row=1, column=1, sticky="w", padx=10, pady=2)

        # Generated Password Display
        self.password_entry = ctk.CTkEntry(main_frame, font=("Courier", 12), justify="center")
        self.password_entry.pack(fill="x", pady=10)
        self.password_entry.bind("<FocusIn>", lambda e: self.password_entry.select_range(0, 'end'))

        # Strength Indicator (Optional)
        if ZXCVBN_AVAILABLE:
            self.strength_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
            self.strength_frame.pack(fill="x", pady=5)
            ctk.CTkLabel(self.strength_frame, text="Strength:", anchor="w").pack(side="left")
            self.strength_label = ctk.CTkLabel(self.strength_frame, text="Checking...", anchor="w", justify="left")
            self.strength_label.pack(side="left", padx=5, fill="x", expand=True)
            self.strength_bar = ctk.CTkProgressBar(self.strength_frame, height=10)
            self.strength_bar.set(0)
            self.strength_bar.pack(fill="x", pady=(0, 5))


        # Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=10)
        button_frame.columnconfigure((0, 1, 2), weight=1)

        regenerate_button = ctk.CTkButton(button_frame, text="Regenerate", command=self._update_password)
        regenerate_button.grid(row=0, column=0, padx=5)

        copy_button = ctk.CTkButton(button_frame, text="Copy & Use", command=self._on_copy_use)
        copy_button.grid(row=0, column=1, padx=5)

        cancel_button = ctk.CTkButton(button_frame, text="Cancel", command=self._on_cancel, fg_color="grey")
        cancel_button.grid(row=0, column=2, padx=5)

    def _update_length_label(self, value: int):
        self.length_label.configure(text=str(value))
        self._update_password()

    def _update_password(self):
        """Generates and displays a new password based on current settings."""
        length = self.length_slider_var.get()
        use_lower = self.use_lower_var.get()
        use_upper = self.use_upper_var.get()
        use_digits = self.use_digits_var.get()
        use_symbols = self.use_symbols_var.get()

        pwd = SecurityManager.generate_password(length, use_lower, use_upper, use_digits, use_symbols)

        if pwd:
            self.generated_password = pwd
            self.password_entry.delete(0, "end")
            self.password_entry.insert(0, pwd)
            self._update_strength_indicator(pwd)
        else:
            self.generated_password = None
            self.password_entry.delete(0, "end")
            self.password_entry.insert(0, "Select options")
            self._update_strength_indicator("")


    def _update_strength_indicator(self, password: str):
        """Updates the password strength label and progress bar."""
        if not ZXCVBN_AVAILABLE: return

        if not password:
            self.strength_label.configure(text="N/A")
            self.strength_bar.set(0)
            return

        strength = SecurityManager.check_password_strength(password)
        score = strength['score'] # 0-4
        feedback = strength['feedback']
        crack_time = strength['crack_time_display']

        # Basic color coding (adjust colors as needed)
        colors = ["#D32F2F", "#EF6C00", "#FDD835", "#7CB342", "#43A047"] # Red, Orange, Yellow, Light Green, Green
        color_index = max(0, min(score, len(colors) - 1))
        self.strength_bar.configure(progress_color=colors[color_index])
        self.strength_bar.set((score + 1) / 5.0) # Scale 0-4 score to 0.2-1.0 progress

        self.strength_label.configure(text=f"Score: {score}/4. Est. Crack Time: {crack_time}\n{feedback}")


    def _on_copy_use(self):
        if self.generated_password:
            try:
                 pyperclip.copy(self.generated_password)
                 self.parent._schedule_clipboard_clear() # Ask parent to schedule clear
                 self.destroy() # Close dialog, result is the copied password
            except Exception as e:
                 messagebox.showerror("Clipboard Error", f"Could not copy password: {e}", parent=self)
        else:
             messagebox.showwarning("No Password", "Generate a password first.", parent=self)


    def _on_cancel(self):
        self.generated_password = None # Indicate cancellation
        self.destroy()


class AddEditEntryDialog(ctk.CTkToplevel):
    """Comprehensive dialog for adding or editing password entries."""

    def __init__(self, parent: 'PasswordManagerApp', title: str, entry_data: Optional[Dict[str, Any]] = None, categories: List[Dict[str, Any]] = [], current_key: bytes = None):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.title(title)
        self.geometry("650x750") # Increased size
        self.parent = parent
        self.entry_data = entry_data or {} # Use empty dict if None
        self.categories = categories # List of {'id': int, 'name': str}
        self.current_key = current_key # Needed for decryption/encryption within dialog scope if needed
        self.result: Optional[Dict[str, Any]] = None
        self.password_visible = False

        # To manage dynamic lists
        self.recovery_widgets: List[Dict[str, Any]] = []
        self.custom_field_widgets: List[Dict[str, Any]] = []

        self._create_widgets()
        self._populate_fields()

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.service_entry.focus_set()
        self.wait_window(self)

    def _create_widgets(self):
        """Creates and lays out the widgets using tabs."""
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(pady=10, padx=10, fill="both", expand=True)

        tabview = ctk.CTkTabview(main_frame)
        tabview.pack(fill="both", expand=True, padx=5, pady=5)

        tab_main = tabview.add("Main Info")
        tab_recovery = tabview.add("Recovery")
        tab_custom = tabview.add("Custom Fields")
        tab_notes = tabview.add("Notes")

        self._create_main_info_tab(tab_main)
        self._create_recovery_tab(tab_recovery)
        self._create_custom_fields_tab(tab_custom)
        self._create_notes_tab(tab_notes)

        # --- Buttons ---
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=(5, 10), padx=10, fill="x")
        button_frame.columnconfigure((0, 1), weight=1)

        save_button = ctk.CTkButton(button_frame, text="Save", width=120, command=self._on_save)
        save_button.grid(row=0, column=0, sticky="e", padx=20)

        cancel_button = ctk.CTkButton(button_frame, text="Cancel", width=120, command=self._on_cancel, fg_color="grey")
        cancel_button.grid(row=0, column=1, sticky="w", padx=20)

    def _create_main_info_tab(self, tab: ctk.CTkFrame):
        """Widgets for the Main Info tab."""
        tab.grid_columnconfigure(1, weight=1)

        # Category
        ctk.CTkLabel(tab, text="Category:").grid(row=0, column=0, padx=10, pady=8, sticky="w")
        cat_frame = ctk.CTkFrame(tab, fg_color="transparent")
        cat_frame.grid(row=0, column=1, columnspan=2, padx=10, pady=5, sticky="ew")
        cat_frame.grid_columnconfigure(0, weight=1)
        self.category_var = ctk.StringVar(value="<No Category>") # Default/initial value
        self.category_options = ["<No Category>"] + [c['name'] for c in self.categories]
        self.category_menu = ctk.CTkOptionMenu(cat_frame, variable=self.category_var, values=self.category_options)
        self.category_menu.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        # Optional: Add button to create new category directly
        # new_cat_button = ctk.CTkButton(cat_frame, text="+", width=30, command=self._add_new_category)
        # new_cat_button.grid(row=0, column=1, sticky="w")

        # Service
        ctk.CTkLabel(tab, text="Service/Website:").grid(row=1, column=0, padx=10, pady=8, sticky="w")
        self.service_entry = ctk.CTkEntry(tab)
        self.service_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=5, sticky="ew")

        # Username
        ctk.CTkLabel(tab, text="Username/Email:").grid(row=2, column=0, padx=10, pady=8, sticky="w")
        self.username_entry = ctk.CTkEntry(tab)
        self.username_entry.grid(row=2, column=1, columnspan=2, padx=10, pady=5, sticky="ew")

        # Password
        ctk.CTkLabel(tab, text="Password:").grid(row=3, column=0, padx=10, pady=8, sticky="w")
        pass_frame = ctk.CTkFrame(tab, fg_color="transparent")
        pass_frame.grid(row=3, column=1, columnspan=2, padx=10, pady=5, sticky="ew")
        pass_frame.grid_columnconfigure(0, weight=1)
        self.password_entry = ctk.CTkEntry(pass_frame, show="*")
        self.password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.toggle_button = ctk.CTkButton(pass_frame, text="Show", width=45, command=self._toggle_password_visibility)
        self.toggle_button.grid(row=0, column=1, padx=(0, 5))
        gen_button = ctk.CTkButton(pass_frame, text="Generate", width=70, command=self._generate_password_dialog)
        gen_button.grid(row=0, column=2)

        # Password Strength (Optional)
        if ZXCVBN_AVAILABLE:
             self.strength_label_diag = ctk.CTkLabel(tab, text="Strength: N/A", anchor="w", justify="left", wraplength=450)
             self.strength_label_diag.grid(row=4, column=1, columnspan=2, padx=10, pady=(0, 5), sticky="ew")
             self.strength_bar_diag = ctk.CTkProgressBar(tab, height=8)
             self.strength_bar_diag.set(0)
             self.strength_bar_diag.grid(row=5, column=1, columnspan=2, padx=10, pady=(0, 10), sticky="ew")
             # Update strength when password changes
             self.password_entry.bind("<KeyRelease>", self._update_strength_indicator_dialog, add="+")


        # TOTP Secret Key
        ctk.CTkLabel(tab, text="TOTP Secret Key\n(Base32):").grid(row=6, column=0, padx=10, pady=8, sticky="w")
        self.totp_entry = ctk.CTkEntry(tab)
        self.totp_entry.grid(row=6, column=1, columnspan=2, padx=10, pady=5, sticky="ew")
        # Add info label about Base32?

    def _create_recovery_tab(self, tab: ctk.CTkFrame):
        """Widgets for the Recovery Contacts tab."""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1) # Make scrollable frame expand

        ctk.CTkLabel(tab, text="Add recovery emails or phone numbers associated with this account:", justify="left").grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="w")

        # Frame for the list of contacts
        self.recovery_list_frame = ctk.CTkScrollableFrame(tab, label_text="Recovery Contacts")
        self.recovery_list_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")
        self.recovery_list_frame.grid_columnconfigure(1, weight=1) # Make entry expand

        # Buttons to add contacts
        add_button_frame = ctk.CTkFrame(tab, fg_color="transparent")
        add_button_frame.grid(row=2, column=0, columnspan=3, pady=5)
        add_email_button = ctk.CTkButton(add_button_frame, text="+ Add Email", command=lambda: self._add_recovery_widget('email'))
        add_email_button.pack(side="left", padx=5)
        add_phone_button = ctk.CTkButton(add_button_frame, text="+ Add Phone", command=lambda: self._add_recovery_widget('phone'))
        add_phone_button.pack(side="left", padx=5)


    def _add_recovery_widget(self, contact_type: str, value: str = ""):
        """Adds a row for entering a recovery contact."""
        row_index = len(self.recovery_widgets)
        frame = ctk.CTkFrame(self.recovery_list_frame, fg_color="transparent")
        frame.grid(row=row_index, column=0, columnspan=3, pady=2, sticky="ew")
        frame.grid_columnconfigure(1, weight=1)

        type_label = ctk.CTkLabel(frame, text=f"{contact_type.capitalize()}:", width=50, anchor="w")
        type_label.grid(row=0, column=0, padx=(0, 5), sticky="w")

        entry = ctk.CTkEntry(frame)
        entry.grid(row=0, column=1, sticky="ew", padx=5)
        entry.insert(0, value)

        remove_button = ctk.CTkButton(frame, text="-", width=25, fg_color="grey", command=lambda w=frame: self._remove_widget(w, self.recovery_widgets))
        remove_button.grid(row=0, column=2, padx=(5, 0))

        widget_data = {"frame": frame, "type": contact_type, "entry": entry}
        self.recovery_widgets.append(widget_data)

    def _create_custom_fields_tab(self, tab: ctk.CTkFrame):
        """Widgets for the Custom Fields tab."""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(tab, text="Add any other relevant information (e.g., security questions, PINs):", justify="left").grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Frame for the list of custom fields
        self.custom_list_frame = ctk.CTkScrollableFrame(tab, label_text="Custom Fields")
        self.custom_list_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.custom_list_frame.grid_columnconfigure(1, weight=1) # Name column
        self.custom_list_frame.grid_columnconfigure(3, weight=1) # Value column

        # Button to add custom field
        add_field_button = ctk.CTkButton(tab, text="+ Add Custom Field", command=self._add_custom_field_widget)
        add_field_button.grid(row=2, column=0, pady=5, padx=10, sticky="w")

    def _add_custom_field_widget(self, name: str = "", value: str = "", is_secret: bool = False):
        """Adds a row for entering a custom field."""
        row_index = len(self.custom_field_widgets)
        frame = ctk.CTkFrame(self.custom_list_frame, fg_color="transparent")
        frame.grid(row=row_index, column=0, pady=2, sticky="ew")
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(3, weight=1)

        name_entry = ctk.CTkEntry(frame, placeholder_text="Field Name")
        name_entry.grid(row=0, column=0, columnspan=2, padx=(0, 5), sticky="ew")
        name_entry.insert(0, name)

        value_entry = ctk.CTkEntry(frame, placeholder_text="Field Value")
        value_entry.grid(row=0, column=2, columnspan=2, padx=5, sticky="ew")
        value_entry.insert(0, value)

        secret_var = ctk.BooleanVar(value=is_secret)
        secret_check = ctk.CTkCheckBox(frame, text="Secret", variable=secret_var, width=70)
        secret_check.grid(row=0, column=4, padx=(5, 5))

        remove_button = ctk.CTkButton(frame, text="-", width=25, fg_color="grey", command=lambda w=frame: self._remove_widget(w, self.custom_field_widgets))
        remove_button.grid(row=0, column=5, padx=(5, 0))

        widget_data = {
            "frame": frame,
            "name_entry": name_entry,
            "value_entry": value_entry,
            "secret_var": secret_var
        }
        self.custom_field_widgets.append(widget_data)


    def _create_notes_tab(self, tab: ctk.CTkFrame):
        """Widgets for the Notes tab."""
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        self.notes_textbox = ctk.CTkTextbox(tab)
        self.notes_textbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    def _remove_widget(self, widget_frame: ctk.CTkFrame, widget_list: list):
        """Removes a widget row from a list and destroys the frame."""
        widget_frame.destroy()
        # Find and remove the corresponding dictionary from the list
        for i, item in enumerate(widget_list):
            if item["frame"] == widget_frame:
                del widget_list[i]
                break
         # Re-grid remaining items to avoid gaps (optional, ScrollableFrame handles it okay)
         # self._regrid_widgets(widget_list)

    # def _regrid_widgets(self, widget_list: list):
    #      """Helper to re-apply grid positions after deletion."""
    #      for i, item in enumerate(widget_list):
    #           item["frame"].grid(row=i) # Adjust row index


    def _toggle_password_visibility(self):
        if self.password_visible:
            self.password_entry.configure(show="*")
            self.toggle_button.configure(text="Show")
        else:
            self.password_entry.configure(show="")
            self.toggle_button.configure(text="Hide")
        self.password_visible = not self.password_visible

    def _generate_password_dialog(self):
         gen_dialog = PasswordGeneratorDialog(self)
         if gen_dialog.generated_password:
             self.password_entry.delete(0, "end")
             self.password_entry.insert(0, gen_dialog.generated_password)
             self._update_strength_indicator_dialog() # Update strength for generated pass

    def _update_strength_indicator_dialog(self, event=None):
        """Updates the password strength display within the dialog."""
        if not ZXCVBN_AVAILABLE: return
        password = self.password_entry.get()

        if not password:
            self.strength_label_diag.configure(text="Strength: N/A")
            self.strength_bar_diag.set(0)
            return

        strength = SecurityManager.check_password_strength(password)
        score = strength['score']
        feedback = strength['feedback']
        crack_time = strength['crack_time_display']

        colors = ["#D32F2F", "#EF6C00", "#FDD835", "#7CB342", "#43A047"]
        color_index = max(0, min(score, len(colors) - 1))
        self.strength_bar_diag.configure(progress_color=colors[color_index])
        self.strength_bar_diag.set((score + 1) / 5.0)

        self.strength_label_diag.configure(text=f"Strength Score: {score}/4\n{feedback}")


    def _populate_fields(self):
        """Fills the dialog fields with existing data for editing."""
        if not self.entry_data or not self.current_key: return

        # --- Main Info Tab ---
        cat_id = self.entry_data.get('category_id')
        if cat_id:
            cat_name = next((c['name'] for c in self.categories if c['id'] == cat_id), None)
            if cat_name: self.category_var.set(cat_name)
        self.service_entry.insert(0, self.entry_data.get('service_name', ''))
        self.username_entry.insert(0, self.entry_data.get('username', ''))

        # Decrypt Password
        decrypted_password = SecurityManager.decrypt_data(
            self.entry_data.get('nonce'), self.entry_data.get('encrypted_password'), self.current_key
        )
        if decrypted_password is not None:
            self.password_entry.insert(0, decrypted_password)
            self._update_strength_indicator_dialog()
        else:
            self.password_entry.insert(0, "*** DECRYPTION FAILED ***")
            self.password_entry.configure(state="disabled")

        # Decrypt TOTP Secret
        decrypted_totp = SecurityManager.decrypt_data(
            self.entry_data.get('totp_secret_nonce'), self.entry_data.get('encrypted_totp_secret'), self.current_key
        )
        if decrypted_totp:
             self.totp_entry.insert(0, decrypted_totp)


        # --- Recovery Tab ---
        contacts = self.entry_data.get('recovery_contacts', [])
        for contact in contacts:
            self._add_recovery_widget(contact['contact_type'], contact['value'])

        # --- Custom Fields Tab ---
        custom_fields = self.entry_data.get('custom_fields', [])
        for field in custom_fields:
            # Decrypt custom field value
            decrypted_value = SecurityManager.decrypt_data(
                field.get('field_value_nonce'), field.get('encrypted_field_value'), self.current_key
            )
            self._add_custom_field_widget(
                field.get('field_name', ''),
                decrypted_value or "*** DECRYPTION FAILED ***",
                bool(field.get('is_secret', 0))
            )

        # --- Notes Tab ---
        self.notes_textbox.insert("1.0", self.entry_data.get('notes', ''))


    def _validate_input(self) -> bool:
        if not self.service_entry.get().strip():
            messagebox.showwarning("Input Error", "Service/Website name cannot be empty.", parent=self)
            return False
        if not self.username_entry.get().strip():
            messagebox.showwarning("Input Error", "Username/Email cannot be empty.", parent=self)
            return False
        if self.password_entry.cget('state') == 'disabled': # Check if decryption failed
             messagebox.showerror("Input Error", "Cannot save entry with failed password decryption.", parent=self)
             return False
        # Add validation for TOTP format (basic Base32 check?) if desired
        # Add validation for custom field names (non-empty?)
        for widget_data in self.custom_field_widgets:
             if not widget_data["name_entry"].get().strip():
                  messagebox.showwarning("Input Error", "Custom field names cannot be empty.", parent=self)
                  return False

        return True

    def _on_save(self):
        if not self._validate_input() or not self.current_key:
            return

        # --- Collect Data from Widgets ---
        selected_cat_name = self.category_var.get()
        category_id = None
        if selected_cat_name != "<No Category>":
            category_id = next((c['id'] for c in self.categories if c['name'] == selected_cat_name), None)
            # Handle case where category might have been deleted while dialog was open? Unlikely but possible.

        password_plain = self.password_entry.get()
        totp_secret_plain = self.totp_entry.get().strip()

        # Encrypt password
        try:
             pass_nonce, encrypted_pass = SecurityManager.encrypt_data(password_plain, self.current_key)
        except (ValueError, TypeError) as e:
             messagebox.showerror("Encryption Error", f"Failed to encrypt password: {e}", parent=self)
             return

        # Encrypt TOTP secret (if present)
        totp_nonce, encrypted_totp = None, None
        if totp_secret_plain:
            try:
                 totp_nonce, encrypted_totp = SecurityManager.encrypt_data(totp_secret_plain, self.current_key)
            except (ValueError, TypeError) as e:
                 messagebox.showerror("Encryption Error", f"Failed to encrypt TOTP secret: {e}", parent=self)
                 return

        # Collect recovery contacts
        recovery_contacts = []
        for widget_data in self.recovery_widgets:
            value = widget_data["entry"].get().strip()
            if value:
                recovery_contacts.append({"type": widget_data["type"], "value": value})

        # Collect and encrypt custom fields
        custom_fields = []
        for widget_data in self.custom_field_widgets:
             name = widget_data["name_entry"].get().strip()
             value_plain = widget_data["value_entry"].get() # Don't strip value
             is_secret = widget_data["secret_var"].get()

             if name: # Only save if name is present
                  try:
                       # Encrypt value (always encrypt for consistency, use is_secret for masking)
                       val_nonce, encrypted_val = SecurityManager.encrypt_data(value_plain, self.current_key)
                       custom_fields.append({
                           "name": name,
                           "nonce": val_nonce,
                           "encrypted_value": encrypted_val,
                           "is_secret": 1 if is_secret else 0
                       })
                  except (ValueError, TypeError) as e:
                       messagebox.showerror("Encryption Error", f"Failed to encrypt custom field '{name}': {e}", parent=self)
                       return # Stop saving if any field fails

        # --- Prepare Result Dictionary ---
        self.result = {
            "id": self.entry_data.get("id"), # Keep ID for updates
            "category_id": category_id,
            "service_name": self.service_entry.get().strip(),
            "username": self.username_entry.get().strip(),
            "nonce": pass_nonce,
            "encrypted_password": encrypted_pass,
            "totp_secret_nonce": totp_nonce,
            "encrypted_totp_secret": encrypted_totp,
            "notes": self.notes_textbox.get("1.0", "end-1c").strip(),
            "recovery_contacts": recovery_contacts,
            "custom_fields": custom_fields,
            # Include plain text only if absolutely needed by caller, prefer not to
            # "password_plain": password_plain # Usually not needed after encryption
        }
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()

# --- Main Application ---

class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_NAME)
        self.geometry("1000x750") # Increased size
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self._master_key: Optional[bytes] = None
        self._db_manager: Optional[DatabaseManager] = None
        self._security_manager = SecurityManager()
        self._clipboard_clear_job: Optional[str] = None
        self._totp_display_job: Optional[str] = None
        self._categories: List[Dict[str, Any]] = [] # Cache categories
        self.selected_category_id: Optional[int] = None # Track selected category filter

        # --- Attempt to unlock vault ---
        if not self._unlock_vault():
            self.quit()
            return

        # --- Initialize Database ---
        try:
            self._db_manager = DatabaseManager(DB_FILENAME)
            self._db_manager.connect()
            self._db_manager.initialize_schema()
            self._load_categories() # Load categories into cache
        except Exception as e:
             messagebox.showerror("Initialization Error", f"Failed to initialize application: {e}")
             self.quit()
             return

        # --- Create Widgets ---
        self._create_widgets()
        self._update_category_list() # Populate sidebar
        self._load_entries_into_treeview() # Load initial entries ("All")

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _unlock_vault(self) -> bool:
        # (Similar to previous version, handles salt creation/loading and key derivation)
        # ... [Code from previous _unlock_vault is largely reusable here] ...
        # Ensure it uses MASTER_SALT_FILENAME and DB_FILENAME constants
        master_salt: Optional[bytes] = None
        salt_path = MASTER_SALT_FILENAME
        salt_exists = os.path.exists(salt_path)

        if salt_exists:
            try:
                with open(salt_path, 'rb') as f:
                    master_salt = f.read()
                if not master_salt or len(master_salt) < 16:
                    messagebox.showerror("Security Error", f"Master salt file '{salt_path}' is corrupted or empty.")
                    return False
            except IOError as e:
                 messagebox.showerror("File Error", f"Could not read master salt file: {e}")
                 return False
        else:
            confirm = messagebox.askyesno("Setup New Vault", "No existing vault found. Do you want to create a new one?\n"
                                            f"(This will create '{DB_FILENAME}' and '{salt_path}')")
            if not confirm: return False

            while True:
                new_password = ctk.CTkInputDialog(text="Enter a strong NEW Master Password:", title="Create Master Password").get_input()
                if not new_password: return False
                confirm_password = ctk.CTkInputDialog(text="Confirm your NEW Master Password:", title="Confirm Master Password").get_input()
                if not confirm_password: return False

                if new_password == confirm_password:
                    master_salt = self._security_manager.generate_salt()
                    try:
                        with open(salt_path, 'wb') as f: f.write(master_salt)
                        self._master_key = self._security_manager.derive_key(new_password, master_salt)
                        messagebox.showinfo("Vault Created", f"New vault created successfully.\nKeep '{salt_path}' safe!")
                        del new_password, confirm_password # Clear from memory
                        return True
                    except IOError as e:
                        messagebox.showerror("File Error", f"Could not save master salt file: {e}")
                        if os.path.exists(salt_path): os.remove(salt_path)
                        return False
                    except ValueError as e:
                        messagebox.showerror("Security Error", f"Failed to derive key: {e}")
                        return False
                else:
                    messagebox.showwarning("Password Mismatch", "Passwords do not match. Try again.")

        # Prompt for existing password
        password = ctk.CTkInputDialog(text="Enter your Master Password:", title="Unlock Vault").get_input()
        if not password: return False

        try:
            self._master_key = self._security_manager.derive_key(password, master_salt)
            del password # Clear from memory
            # Add test decryption here if implemented
            self.set_status("Vault Unlocked.")
            return True
        except ValueError as e:
            messagebox.showerror("Unlock Failed", f"Failed to derive key (wrong password?): {e}")
            return False
        except Exception as e:
             messagebox.showerror("Unlock Failed", f"An unexpected error occurred: {e}")
             return False
        # --- End of _unlock_vault section ---


    def _create_widgets(self):
        """Creates the main UI elements with category sidebar."""
        self.grid_columnconfigure(1, weight=1) # Main content area
        self.grid_rowconfigure(0, weight=1)    # Main content row
        self.grid_rowconfigure(1, weight=0)    # Status bar row

        # --- Left Sidebar (Categories) ---
        sidebar_frame = ctk.CTkFrame(self, width=180, corner_radius=0)
        sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsw")
        sidebar_frame.grid_rowconfigure(2, weight=1) # Make scrollable frame expand

        logo_label = ctk.CTkLabel(sidebar_frame, text="Categories", font=ctk.CTkFont(size=20, weight="bold"))
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.category_frame = ctk.CTkScrollableFrame(sidebar_frame, label_text="")
        self.category_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        self.category_frame.grid_columnconfigure(0, weight=1)

        # Add Category button
        add_cat_button = ctk.CTkButton(sidebar_frame, text="+ New Category", command=self._add_category)
        add_cat_button.grid(row=1, column=0, padx=20, pady=10)


        # --- Right Content Area ---
        main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        main_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1) # Treeview row expands

        # Search Bar
        search_frame = ctk.CTkFrame(main_frame)
        search_frame.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search Service, Username, Notes, Category...", textvariable=self.search_var)
        self.search_entry.pack(fill="x", padx=5, pady=5)
        self.search_var.trace_add("write", lambda *args: self._filter_entries()) # Trigger search on typing

        # Treeview
        tree_frame = ctk.CTkFrame(main_frame)
        tree_frame.grid(row=1, column=0, padx=10, pady=(5, 5), sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        style = ttk.Style(self) # Use ttk for Treeview
        # Configure style for better appearance if needed

        self.tree = ttk.Treeview(tree_frame, columns=("Service", "Username", "Category"), show="headings", selectmode="browse")
        self.tree.heading("Service", text="Service / Website")
        self.tree.heading("Username", text="Username / Email")
        self.tree.heading("Category", text="Category")
        self.tree.column("Service", width=250, anchor=W)
        self.tree.column("Username", width=250, anchor=W)
        self.tree.column("Category", width=150, anchor=W)

        scrollbar_y = ctk.CTkScrollbar(tree_frame, command=self.tree.yview)
        scrollbar_x = ctk.CTkScrollbar(tree_frame, command=self.tree.xview, orientation="horizontal")
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")

        self.tree.bind("<<TreeviewSelect>>", self._on_entry_select)
        self.tree.bind("<Double-1>", self._edit_entry) # Double-click to edit

        # Button Panel below Treeview
        button_panel = ctk.CTkFrame(main_frame)
        button_panel.grid(row=2, column=0, padx=10, pady=(5, 10), sticky="ew")
        # Add buttons like Add, Edit, Delete, Copy User, Copy Pass, Show TOTP
        btn_width = 100
        btn_pad = 5
        self.add_button = ctk.CTkButton(button_panel, text="Add New", width=btn_width, command=self._add_entry)
        self.add_button.pack(side="left", padx=btn_pad)
        self.edit_button = ctk.CTkButton(button_panel, text="Edit", width=btn_width, command=self._edit_entry, state="disabled")
        self.edit_button.pack(side="left", padx=btn_pad)
        self.delete_button = ctk.CTkButton(button_panel, text="Delete", width=btn_width, command=self._delete_entry, state="disabled", fg_color="#D32F2F", hover_color="#C62828")
        self.delete_button.pack(side="left", padx=btn_pad)
        self.copy_user_button = ctk.CTkButton(button_panel, text="Copy User", width=btn_width, command=self._copy_username, state="disabled")
        self.copy_user_button.pack(side="left", padx=btn_pad)
        self.copy_pass_button = ctk.CTkButton(button_panel, text="Copy Pass", width=btn_width, command=self._copy_password, state="disabled")
        self.copy_pass_button.pack(side="left", padx=btn_pad)
        self.show_totp_button = ctk.CTkButton(button_panel, text="Show TOTP", width=btn_width, command=self._show_totp, state="disabled")
        self.show_totp_button.pack(side="left", padx=btn_pad)

        # --- Status Bar ---
        self.status_bar = ctk.CTkLabel(self, text="Initializing...", anchor=W)
        self.status_bar.grid(row=1, column=1, padx=10, pady=(0, 5), sticky=EW)


    def set_status(self, message: str, clear_after_ms: Optional[int] = None):
        """Updates the status bar message."""
        self.status_bar.configure(text=message)
        if clear_after_ms:
            self.after(clear_after_ms, lambda: self.status_bar.configure(text="")) # Clear after delay


    # --- Category Management ---
    def _load_categories(self):
         """Loads categories from DB into the internal cache."""
         if not self._db_manager: return
         self._categories = self._db_manager.get_all_categories()

    def _update_category_list(self):
        """Updates the category list display in the sidebar."""
        # Clear existing buttons/labels (except Add button maybe)
        for widget in self.category_frame.winfo_children():
            widget.destroy()

        # Add "All Entries" option
        all_button = ctk.CTkRadioButton(self.category_frame, text="All Entries", value=-1,  # Use -1 or None for 'All'
                                         command=lambda: self._filter_by_category(None), radiobutton_width=16, radiobutton_height=16)
        all_button.grid(row=0, column=0, pady=(0, 5), padx=5, sticky="w")
        # Select "All" by default
        all_button.select()
        self.selected_category_id = None

        # Add buttons for each category
        for idx, category in enumerate(self._categories, start=1):
            cat_button = ctk.CTkRadioButton(self.category_frame, text=category['name'], value=category['id'],
                                            command=lambda cat_id=category['id']: self._filter_by_category(cat_id),
                                            radiobutton_width=16, radiobutton_height=16)
            cat_button.grid(row=idx, column=0, pady=(0, 5), padx=5, sticky="w")


    def _add_category(self):
         """Prompts user for a new category name and adds it."""
         if not self._db_manager: return
         new_name = ctk.CTkInputDialog(text="Enter new category name:", title="Add Category").get_input()
         if new_name and new_name.strip():
              new_id = self._db_manager.add_category(new_name.strip())
              if new_id is not None:
                  self._load_categories() # Refresh cache
                  self._update_category_list() # Update UI
                  self.set_status(f"Category '{new_name.strip()}' added.")
              # Else: error message shown by db_manager

    def _filter_by_category(self, category_id: Optional[int]):
         """Sets the category filter and reloads the treeview."""
         self.selected_category_id = category_id
         self.set_status(f"Filtering by category ID: {category_id}") # Debug/Status
         self._load_entries_into_treeview()


    def _filter_entries(self, *args):
         """Filters entries based on search term and selected category."""
         self._load_entries_into_treeview() # Reload with current filters


    # --- Entry Management ---
    def _load_entries_into_treeview(self):
        """Clears and reloads entries based on filters."""
        if not self._db_manager: return
        for item in self.tree.get_children():
            self.tree.delete(item)

        search_term = self.search_var.get().strip()
        search_term = search_term if search_term else None # Use None if empty

        try:
            entries = self._db_manager.get_entries_summary(category_id=self.selected_category_id, search_term=search_term)
            for entry in entries:
                category_name = entry.get('category_name', '<None>') # Handle null category
                self.tree.insert("", END, iid=entry['id'], values=(entry['service_name'], entry['username'], category_name))
        except Exception as e:
             messagebox.showerror("Load Error", f"Failed to load entries: {e}", parent=self)
        finally:
             self._update_button_states()


    def _get_selected_entry_id(self) -> Optional[int]:
        selected_items = self.tree.selection()
        return int(selected_items[0]) if selected_items else None

    def _on_entry_select(self, event=None):
        self._update_button_states()

    def _update_button_states(self):
        selected_id = self._get_selected_entry_id()
        state = "normal" if selected_id is not None else "disabled"

        self.edit_button.configure(state=state)
        self.delete_button.configure(state=state)
        self.copy_user_button.configure(state=state)
        self.copy_pass_button.configure(state=state)

        # Check if selected entry has TOTP secret to enable button
        totp_state = "disabled"
        if selected_id and self._db_manager and self._master_key:
             # Quick check - does the entry *have* an encrypted TOTP secret?
             # Avoid full decryption just to check existence.
             # This requires modifying get_entry_details or adding a specific check method.
             # Simpler for now: enable if selected, check on click.
             # Better: Add 'has_totp' boolean to get_entries_summary
             # Quick & dirty check (might hit DB often):
             details = self._db_manager.get_entry_full_details(selected_id)
             if details and details.get('encrypted_totp_secret'):
                 totp_state = "normal"

        self.show_totp_button.configure(state=totp_state)

    def _schedule_clipboard_clear(self):
         """Schedules the clipboard to be cleared."""
         if self._clipboard_clear_job:
             self.after_cancel(self._clipboard_clear_job)
         self._clipboard_clear_job = self.after(CLIPBOARD_CLEAR_DELAY_MS, self._clear_clipboard)
         print(f"Clipboard clear scheduled in {CLIPBOARD_CLEAR_DELAY_MS} ms.")

    def _clear_clipboard(self):
        try:
            pyperclip.copy('')
            self.set_status("Clipboard cleared.", 3000)
        except Exception as e:
            print(f"Warning: Could not clear clipboard - {e}")
        finally:
             self._clipboard_clear_job = None

    def _copy_to_clipboard(self, text: str, item_name: str):
        if not text:
             messagebox.showwarning("Copy Error", f"{item_name} is empty.", parent=self)
             return
        try:
            pyperclip.copy(text)
            self.set_status(f"{item_name} copied to clipboard. Will clear automatically.", CLIPBOARD_CLEAR_DELAY_MS + 500)
            self._schedule_clipboard_clear()
        except Exception as e:
             messagebox.showerror("Clipboard Error", f"Could not copy {item_name}: {e}", parent=self)


    def _add_entry(self):
        if not self._master_key or not self._db_manager: return
        self._load_categories() # Ensure categories are fresh for the dialog

        dialog = AddEditEntryDialog(self, title="Add New Entry", categories=self._categories, current_key=self._master_key)
        if dialog.result:
            data = dialog.result
            entry_id = self._db_manager.add_entry(data)
            if entry_id is not None:
                 self.set_status(f"Entry '{data['service_name']}' added.")
                 self._load_entries_into_treeview() # Refresh view
            # Else: error shown by db_manager

    def _edit_entry(self, event=None): # Allow activation by double-click event
        if not self._master_key or not self._db_manager: return
        entry_id = self._get_selected_entry_id()
        if entry_id is None: return

        self._load_categories() # Refresh categories
        entry_data = self._db_manager.get_entry_full_details(entry_id)
        if not entry_data:
            messagebox.showerror("Error", "Could not retrieve entry details.", parent=self)
            return

        dialog = AddEditEntryDialog(self, title="Edit Entry", entry_data=entry_data, categories=self._categories, current_key=self._master_key)
        if dialog.result:
             updated_data = dialog.result
             updated_data['id'] = entry_id # Ensure ID is in the dict for update method
             success = self._db_manager.update_entry(entry_id, updated_data)
             if success:
                 self.set_status(f"Entry '{updated_data['service_name']}' updated.")
                 self._load_entries_into_treeview()
             # Else: error shown by db_manager

    def _delete_entry(self):
        if not self._db_manager: return
        entry_id = self._get_selected_entry_id()
        if entry_id is None: return

        try:
            # Get details for confirmation message
            details = self.tree.item(entry_id)['values']
            service = details[0]
            username = details[1]
        except (IndexError, KeyError):
             service, username = "Selected Entry", "" # Fallback

        if messagebox.askyesno("Confirm Delete", f"Delete entry?\n\nService: {service}\nUsername: {username}", parent=self):
            if self._db_manager.delete_entry(entry_id):
                self.set_status(f"Entry '{service}' deleted.")
                self._load_entries_into_treeview() # Refresh list
            # Else: error shown by db_manager


    def _copy_username(self):
        entry_id = self._get_selected_entry_id()
        if entry_id is None: return
        try:
            username = self.tree.item(entry_id)['values'][1]
            self._copy_to_clipboard(username, "Username")
        except (IndexError, KeyError) as e:
             messagebox.showerror("Error", f"Could not retrieve username: {e}", parent=self)


    def _copy_password(self):
        if not self._master_key or not self._db_manager: return
        entry_id = self._get_selected_entry_id()
        if entry_id is None: return

        entry_data = self._db_manager.get_entry_full_details(entry_id)
        if not entry_data:
            messagebox.showerror("Error", "Could not retrieve entry details.", parent=self)
            return

        decrypted_password = self._security_manager.decrypt_data(
            entry_data.get('nonce'), entry_data.get('encrypted_password'), self._master_key
        )

        if decrypted_password is not None:
            self._copy_to_clipboard(decrypted_password, "Password")
            del decrypted_password # Clear from memory
        else:
            messagebox.showerror("Decryption Failed", "Could not decrypt password.", parent=self)


    def _show_totp(self):
        """Decrypts and displays the TOTP code temporarily."""
        if not self._master_key or not self._db_manager: return
        entry_id = self._get_selected_entry_id()
        if entry_id is None: return

        entry_data = self._db_manager.get_entry_full_details(entry_id)
        if not entry_data:
             messagebox.showerror("Error", "Could not retrieve entry details.", parent=self)
             return

        decrypted_secret = self._security_manager.decrypt_data(
            entry_data.get('totp_secret_nonce'), entry_data.get('encrypted_totp_secret'), self._master_key
        )

        if not decrypted_secret:
            messagebox.showwarning("TOTP Error", "No TOTP secret found or could not decrypt.", parent=self)
            return

        totp_code = self._security_manager.generate_totp_code(decrypted_secret)
        del decrypted_secret # Clear secret from memory

        if totp_code:
            # Display in a temporary, non-modal window or status bar
            self.set_status(f"TOTP Code: {totp_code} (Clearing soon)", TOTP_DISPLAY_DURATION_MS)
            # Optionally copy to clipboard as well
            # self._copy_to_clipboard(totp_code, "TOTP Code")
        else:
             messagebox.showerror("TOTP Error", "Failed to generate TOTP code. Is the secret key valid (Base32)?", parent=self)


    def _on_closing(self):
        """Handles application closing actions."""
        print("Closing application...")
        if self._clipboard_clear_job:
            self.after_cancel(self._clipboard_clear_job)
            self._clear_clipboard()

        if self._db_manager:
            self._db_manager.close()
            print("Database connection closed.")

        self._master_key = None
        print("Master key cleared.")
        self.destroy()


# --- Run Application ---
if __name__ == "__main__":
    app = None
    try:
        app = PasswordManagerApp()
        # Only run mainloop if unlock was successful (checked inside __init__)
        if hasattr(app, '_master_key') and app._master_key:
            app.mainloop()
        else:
             print("Application initialization failed or was cancelled. Exiting.")
    except Exception as e:
        print(f"CRITICAL ERROR: An unhandled exception occurred: {e}")
        import traceback
        traceback.print_exc() # Print stack trace for debugging
        # Attempt cleanup
        if app and hasattr(app, '_db_manager') and app._db_manager:
            try: app._db_manager.close()
            except: pass
    finally:
        # Final check if app exists but mainloop might not have run/finished
        if app and hasattr(app, '_db_manager') and app._db_manager and app._db_manager._conn:
            try: app._db_manager.close(); print("Ensured DB closed.")
            except: pass