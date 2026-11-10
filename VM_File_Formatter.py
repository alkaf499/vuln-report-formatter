import sys
import os
import re
import ssl
import json
import hmac
import struct
import base64
import urllib.parse
import urllib.request
import urllib.error
import getpass
import pandas as pd
import csv
from datetime import datetime
from hashlib import sha256, pbkdf2_hmac
from openpyxl import load_workbook
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog, QTextEdit,
    QProgressBar, QFrame, QMessageBox, QGraphicsDropShadowEffect,
    QTabWidget, QComboBox, QGroupBox, QSizePolicy, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor


# ---------------------------------------------------------------------------
# Resolve the directory where THIS script lives.
# bu_database.json is expected to sit right next to it.
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BU_DB_PATH = os.path.join(SCRIPT_DIR, "bu_database.json")


APP_NAME = "Vuln Report Formatter"


# ---------------------------------------------------------------------------
# Qualys connection settings
# ---------------------------------------------------------------------------
# NOTHING ORGANISATION-SPECIFIC IS SHIPPED IN THIS FILE. The pod URL, the API
# username and the password token are all blank by default and must be supplied
# per deployment, so this script can be shared or published as-is.
#
# Set them with environment variables (recommended — nothing to commit):
#
#     export QUALYS_API_URL="https://qualysapi.qualys.com"
#     export QUALYS_API_USER="<your api username>"
#
# Qualys has one base URL per platform ("pod"); use the one your subscription
# lives on. Check Help > About in the Qualys UI if you are unsure. Examples:
#     US  https://qualysapi.qualys.com        https://qualysapi.qg2.apps.qualys.com
#     EU  https://qualysapi.qualys.eu         https://qualysapi.qg2.apps.qualys.eu
#     IN  https://qualysapi.qg1.apps.qualys.in
# (That list is not exhaustive and Qualys may add pods.)
#
# The fallbacks below are for deployments where environment variables are not
# workable. Filling them in puts your pod and username into the source file, so
# do not commit them to a shared repository.
_QUALYS_API_URL_ENV = "QUALYS_API_URL"
_QUALYS_API_USER_ENV = "QUALYS_API_USER"

_QUALYS_API_URL_FALLBACK = ""
_QUALYS_API_USER_FALLBACK = ""


def get_qualys_api_url() -> str:
    """Qualys pod base URL, from the environment or the in-file fallback."""
    return (os.environ.get(_QUALYS_API_URL_ENV, "").strip()
            or _QUALYS_API_URL_FALLBACK).rstrip("/")


def get_qualys_api_user() -> str:
    """Qualys API username, from the environment or the in-file fallback."""
    return os.environ.get(_QUALYS_API_USER_ENV, "").strip() or _QUALYS_API_USER_FALLBACK


# ---------------------------------------------------------------------------
# Qualys credential vault
# ---------------------------------------------------------------------------
# The API password is NEVER stored in clear text in this file. It is kept as an
# encrypted token (see _QUALYS_PWD_TOKEN) and only decrypted in memory, at the
# moment an API request is built. The plaintext lives in a local variable for
# the duration of a single request and is then discarded.
#
# !! THE VAULT SECRET IS NOT SHIPPED WITH THIS SCRIPT. !!
#
# Before the Qualys tab can work you must supply one, by either:
#
#   1. (recommended) exporting an environment variable:
#          export VAULT_SECRET="<a long random passphrase>"
#          setx    VAULT_SECRET "<a long random passphrase>"   (Windows)
#
#   2. or filling in _VAULT_SECRET_FALLBACK below. Note that doing so puts the
#      secret back in the source file, which defeats most of the point: anyone
#      who can read the script can then decrypt the token.
#
# The same secret must be used on every machine that needs to decrypt the same
# token. Changing the secret invalidates every existing token, so re-run
#     python VM_File_Formatter.py --encrypt-qualys-password
# afterwards and paste the new token below.

# Encrypted form of the API password. Generate one with:
#     python VM_File_Formatter.py --encrypt-qualys-password
_QUALYS_PWD_TOKEN = ""

# Name of the environment variable checked first for the vault secret.
_VAULT_SECRET_ENV = "VAULT_SECRET"

# In-file fallback. Intentionally empty — see the note above.
_VAULT_SECRET_FALLBACK = b""

_VAULT_ITERATIONS = 200_000


class VaultNotConfigured(RuntimeError):
    """Raised when the vault secret or the password token has not been set."""


def _vault_secret() -> bytes:
    """Return the vault secret, preferring the environment variable."""
    env_value = os.environ.get(_VAULT_SECRET_ENV, "").strip()
    if env_value:
        return env_value.encode("utf-8")

    if _VAULT_SECRET_FALLBACK:
        return _VAULT_SECRET_FALLBACK

    raise VaultNotConfigured(
        f"No vault secret configured. Set the {_VAULT_SECRET_ENV} environment "
        f"variable to your passphrase, or fill in _VAULT_SECRET_FALLBACK in "
        f"{os.path.basename(__file__)}. The same value must be used everywhere "
        f"the same token is decrypted."
    )


def vault_is_configured() -> bool:
    """Cheap check for the UI: can we decrypt a password at all right now?"""
    try:
        _vault_secret()
    except VaultNotConfigured:
        return False
    return bool(_QUALYS_PWD_TOKEN)


def qualys_config_problems():
    """Return a list of human-readable reasons the Qualys tab cannot run yet."""
    problems = []

    if not get_qualys_api_url():
        problems.append(f"pod URL (set {_QUALYS_API_URL_ENV})")
    if not get_qualys_api_user():
        problems.append(f"API username (set {_QUALYS_API_USER_ENV})")

    try:
        _vault_secret()
    except VaultNotConfigured:
        problems.append(f"vault secret (set {_VAULT_SECRET_ENV})")

    if not _QUALYS_PWD_TOKEN:
        problems.append("password token (run --encrypt-qualys-password)")

    return problems


def _vault_keystream(key: bytes, salt: bytes, length: int) -> bytes:
    """Derive a keystream of `length` bytes from key + salt using HMAC-SHA256."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key, salt + struct.pack(">I", counter), sha256).digest())
        counter += 1
    return bytes(out[:length])


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret into a portable base64 token (salt + ciphertext)."""
    salt = os.urandom(16)
    key = pbkdf2_hmac("sha256", _vault_secret(), salt, _VAULT_ITERATIONS, dklen=32)
    data = plaintext.encode("utf-8")
    ks = _vault_keystream(key, salt, len(data))
    cipher = bytes(a ^ b for a, b in zip(data, ks))
    return base64.b64encode(salt + cipher).decode("ascii")


def decrypt_secret(token: str) -> str:
    """Decrypt a token produced by encrypt_secret back into plaintext."""
    raw = base64.b64decode(token.encode("ascii"))
    salt, cipher = raw[:16], raw[16:]
    key = pbkdf2_hmac("sha256", _vault_secret(), salt, _VAULT_ITERATIONS, dklen=32)
    ks = _vault_keystream(key, salt, len(cipher))
    data = bytes(a ^ b for a, b in zip(cipher, ks))
    return data.decode("utf-8")


def get_qualys_password() -> str:
    """Return the decrypted API password. Called only when a request is made."""
    if not _QUALYS_PWD_TOKEN:
        raise VaultNotConfigured(
            "No Qualys password token stored. Run:\n"
            f"    python {os.path.basename(__file__)} --encrypt-qualys-password\n"
            "and paste the printed value into _QUALYS_PWD_TOKEN."
        )
    try:
        return decrypt_secret(_QUALYS_PWD_TOKEN)
    except VaultNotConfigured:
        raise
    except Exception as e:
        raise VaultNotConfigured(
            f"Could not decrypt the stored password token ({e}). This usually "
            f"means the vault secret does not match the one used to create it. "
            f"Re-run --encrypt-qualys-password with the current secret."
        ) from e


# ---------------------------------------------------------------------------
# Column visibility rules — SINGLE SOURCE OF TRUTH
# ---------------------------------------------------------------------------
# Both the Format tab (FileFormatter) and the Group by BU tab (BUGrouper) need
# to answer the same question: "given these columns, which ones stay visible?"
# They used to answer it with two separate copies of the logic, which had
# already drifted apart. Everything now routes through detect_columns_to_keep().
#
# To add support for a new scanner export, add one branch here and nothing else.

# Sentinel first-column name used after the Asset Vuln Datalist preamble rows
# have been stripped, since that format has no distinctive first column.
ASSET_VULN_DATALIST_KEY = "__asset_vuln_datalist__"

_DATALIST_COLUMNS = ["Title", "Asset Name", "Asset IPV4", "Results", "Solution"]

_IP_SCAN_COLUMNS = ["IP", "DNS", "Title", "CVE ID", "OS", "Results", "Solution"]


def detect_columns_to_keep(columns, first_column_override=None):
    """Work out which columns should stay visible for a given set of columns.

    Returns a ``(rule_name, columns_to_keep)`` tuple. ``rule_name`` is None and
    the list is empty when nothing matched, which callers treat as "leave every
    column visible".

    ``first_column_override`` lets FileFormatter pass the sentinel key, or the
    header value it recovered from the first data row, instead of the literal
    DataFrame column name.
    """
    cols = [str(c).strip() for c in columns]

    if first_column_override is not None:
        first = str(first_column_override).strip()
    else:
        first = cols[0] if cols else ""

    second = cols[1] if len(cols) > 1 else ""

    if first == ASSET_VULN_DATALIST_KEY:
        return "Asset Vuln Datalist Report", list(_DATALIST_COLUMNS)

    if first == "ID" and second == "WizURL":
        return "ID + WizURL", [
            "Name", "AssetName", "AssetRegion", "LocationPath",
            "SubscriptionName", "Description", "Remediation", "FixedVersion",
        ]

    if first == "ID":
        return "ID", ["DNS", "IP", "Vulnerability Title", "RESULTS", "SOLUTION"]

    if first == "Created At":
        return "Created At", [
            "Title", "Resource Name", "Subscription Name", "Subscription ID",
        ]

    if first == "QID":
        return "QID", list(_DATALIST_COLUMNS)

    if first == "IP":
        return "IP", list(_IP_SCAN_COLUMNS)

    # Fallback: recognise the Asset Vuln Datalist shape by its columns, which
    # covers files that have already been through the formatter once.
    cols_lower = {c.lower() for c in cols}
    if "title" in cols_lower and "asset name" in cols_lower:
        return "Asset Vuln Datalist (matched by columns)", list(_DATALIST_COLUMNS)

    return None, []


class FileFormatter:
    
    def __init__(self, file_path, log_callback=None):
        self.file_path = file_path
        self.df = None
        self.first_column_name = None
        self.columns_to_hide = []
        self.is_csv = False
        self.log = log_callback or print
    
    def _detect_file_type(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                if first_line.startswith('"Asset Vuln Datalist Report"') or first_line.startswith('Asset Vuln Datalist Report'):
                    return "asset_vuln_datalist"
        except:
            pass
        return "unknown"
    
    def _read_csv_raw(self, file_path):
        best_df = None
        best_cols = 0
        
        encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'iso-8859-1']
        delimiters = [',', ';', '\t', '|']
        
        for encoding in encodings:
            for delimiter in delimiters:
                try:
                    df = pd.read_csv(
                        file_path, 
                        sep=delimiter, 
                        header=None, 
                        on_bad_lines='skip', 
                        engine='python', 
                        encoding=encoding,
                        dtype=str
                    )
                    
                    if df.shape[1] > best_cols:
                        best_cols = df.shape[1]
                        best_df = df
                        self.log(f"🔍 Trying encoding='{encoding}', delimiter='{delimiter}': {df.shape[0]} rows × {df.shape[1]} columns")
                        
                        if df.shape[1] >= 5:
                            self.log(f"✅ Found good format: {df.shape[0]} rows × {df.shape[1]} columns")
                            return df
                            
                except Exception as e:
                    continue
        
        if best_df is None or best_cols <= 2:
            self.log(f"🔄 Standard parsing failed, trying line-by-line approach...")
            best_df = self._read_csv_line_by_line(file_path)
        
        return best_df
    
    def _read_csv_line_by_line(self, file_path):
        rows = []
        max_cols = 0
        
        for encoding in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    sample_lines = []
                    for _ in range(20):
                        line = f.readline()
                        if line:
                            sample_lines.append(line)
                    
                    delimiter_counts = {',': 0, ';': 0, '\t': 0, '|': 0}
                    for line in sample_lines:
                        for delim in delimiter_counts:
                            delimiter_counts[delim] += line.count(delim)
                    
                    best_delim = max(delimiter_counts, key=delimiter_counts.get)
                    self.log(f"🔍 Line-by-line: detected delimiter '{best_delim}' (count: {delimiter_counts[best_delim]})")
                    
                    f.seek(0)
                    reader = csv.reader(f, delimiter=best_delim)
                    
                    for row in reader:
                        rows.append(row)
                        if len(row) > max_cols:
                            max_cols = len(row)
                    
                    self.log(f"✅ Line-by-line read: {len(rows)} rows, max {max_cols} columns")
                    break
                    
            except Exception as e:
                self.log(f"⚠️ Encoding {encoding} failed: {e}")
                continue
        
        if not rows:
            self.log(f"❌ Could not read file with any encoding")
            return pd.DataFrame()
        
        normalized_rows = []
        for row in rows:
            if len(row) < max_cols:
                row = row + [''] * (max_cols - len(row))
            normalized_rows.append(row)
        
        df = pd.DataFrame(normalized_rows)
        self.log(f"📊 Created DataFrame: {df.shape[0]} rows × {df.shape[1]} columns")
        
        return df
        
    def load_file(self):
        file_ext = os.path.splitext(self.file_path)[1].lower()
        
        try:
            if file_ext == '.csv':
                file_type = self._detect_file_type(self.file_path)
                
                if file_type == "asset_vuln_datalist":
                    self.log(f"🔍 Detected 'Asset Vuln Datalist Report' format")
                    self.log(f"⏭️ Skipping first 3 junk header rows...")
                    self.df = pd.read_csv(self.file_path, skiprows=3, on_bad_lines='skip', engine='python')
                    self.first_column_name = ASSET_VULN_DATALIST_KEY
                else:
                    self.df = self._read_csv_raw(self.file_path)
                    
                    if self.df is not None and len(self.df) > 0:
                        self.first_column_name = str(self.df.iloc[0, 0]).strip() if pd.notna(self.df.iloc[0, 0]) else ""
                        
                        known_headers = ["ID", "Created At", "QID"]
                        if self.first_column_name in known_headers:
                            new_headers = [
                                str(x).strip() if pd.notna(x) else f"Column_{i}"
                                for i, x in enumerate(self.df.iloc[0])
                            ]
                            self.df.columns = new_headers
                            self.df = self.df.iloc[1:].reset_index(drop=True)
                            self.first_column_name = self.df.columns[0]
                            self.log(f"📋 Promoted first row to column headers")
                    else:
                        self.first_column_name = ""
                
                self.log(f"📊 Loaded CSV: {self.df.shape[0]} rows × {self.df.shape[1]} columns")
                self.log(f"🔍 First column name: '{self.first_column_name}'")
                
                base = os.path.splitext(self.file_path)[0]
                xlsx_path = f"{base}.xlsx"
                self.df.to_excel(xlsx_path, index=False)
                self.log(f"🔄 Converted to Excel format")
                self.file_path = xlsx_path
                
            elif file_ext in ['.xlsx', '.xls']:
                self.df = pd.read_excel(self.file_path)
                self.first_column_name = self.df.columns[0]
                self.log(f"📊 Loaded Excel file: {os.path.basename(self.file_path)}")
            else:
                raise ValueError(f"Unsupported file format: {file_ext}")
            
            self.log(f"🔍 First 5 columns: {list(self.df.columns)[:5]}...")
            return True
            
        except Exception as e:
            self.log(f"❌ Error loading file: {e}")
            import traceback
            self.log(traceback.format_exc())
            return False

    def apply_formatting_rules(self):
        """Pick the visible columns using the shared rule table.

        If no rule matches up front, fall back to hunting for a buried header
        row (the Qualys scan report puts the real header halfway down the file)
        and re-run detection against the restructured frame.
        """
        rule, columns_to_keep = detect_columns_to_keep(
            self.df.columns, self.first_column_name
        )

        if rule:
            self._mark_columns_to_hide(columns_to_keep)
            self.log(f"✅ Applied '{rule}' rule - will hide non-essential columns")
            return

        if self._find_and_apply_ip_header_row():
            rule, columns_to_keep = detect_columns_to_keep(
                self.df.columns, self.first_column_name
            )
            if not columns_to_keep:
                rule, columns_to_keep = "IP header search", list(_IP_SCAN_COLUMNS)
            self._mark_columns_to_hide(columns_to_keep)
            self.log(f"✅ Applied '{rule}' rule after locating the second 'IP' header row")
        else:
            self.log(f"ℹ️ No rule matched '{self.first_column_name}' and no second "
                     f"'IP' header found - keeping original data")
    
    def _find_and_apply_ip_header_row(self):
        ip_count = 0
        
        self.log(f"🔍 Searching for second 'IP' in column A...")
        self.log(f"📊 DataFrame has {len(self.df)} rows and {len(self.df.columns)} columns")
        
        for idx in range(len(self.df)):
            cell_value = str(self.df.iloc[idx, 0]).strip() if pd.notna(self.df.iloc[idx, 0]) else ""
            
            if cell_value == "IP":
                ip_count += 1
                self.log(f"✅ Found 'IP' #{ip_count} at row index {idx}")
                
                if ip_count == 2:
                    new_headers = [str(x).strip() if pd.notna(x) else f"Column_{i}" for i, x in enumerate(self.df.iloc[idx].tolist())]
                    self.log(f"📋 New headers will be: {new_headers[:10]}...")
                    
                    self.df = self.df.iloc[idx + 1:].reset_index(drop=True)
                    self.df.columns = new_headers
                    self.first_column_name = str(self.df.columns[0]) if len(self.df.columns) > 0 else None
                    
                    self.log(f"✅ Restructured! New shape: {self.df.shape}")
                    return True
        
        self.log(f"⚠️ Only found {ip_count} occurrence(s) of 'IP' in column A")
        return False

    def _mark_columns_to_hide(self, columns_to_keep):
        existing_columns_to_keep = [col for col in columns_to_keep if col in self.df.columns]
        missing_columns = [col for col in columns_to_keep if col not in self.df.columns]
        
        if missing_columns:
            self.log(f"⚠️ Columns not found: {missing_columns}")
        
        if existing_columns_to_keep:
            self.log(f"✓ Keeping columns: {existing_columns_to_keep}")
        
        self.columns_to_hide = [col for col in self.df.columns if col not in columns_to_keep]
        if self.columns_to_hide:
            self.log(f"📋 {len(self.columns_to_hide)} columns will be hidden")
    
    def save_file(self, output_path):
        try:
            file_ext = os.path.splitext(output_path)[1].lower()
            
            if file_ext == '.csv':
                self.df.to_csv(output_path, index=False)
                if self.columns_to_hide:
                    self.log(f"⚠️ Note: CSV format doesn't support hidden columns")
            elif file_ext in ['.xlsx', '.xls']:
                self.df.to_excel(output_path, index=False)
                
                if self.columns_to_hide:
                    self._hide_columns_in_excel(output_path)
            
            self.log(f"💾 Saved formatted file successfully!")
            return output_path
            
        except Exception as e:
            self.log(f"❌ Error saving file: {e}")
            return None
    
    def _hide_columns_in_excel(self, file_path):
        try:
            wb = load_workbook(file_path)
            ws = wb.active
            
            for col_idx, col_name in enumerate(self.df.columns, start=1):
                if col_name in self.columns_to_hide:
                    col_letter = ws.cell(row=1, column=col_idx).column_letter
                    ws.column_dimensions[col_letter].hidden = True
            
            wb.save(file_path)
            self.log(f"🙈 Hidden {len(self.columns_to_hide)} columns in Excel")
            
        except Exception as e:
            self.log(f"❌ Error hiding columns: {e}")
    
    def get_info(self):
        return {
            'shape': self.df.shape,
            'columns': list(self.df.columns),
            'preview': self.df.head().to_string()
        }


class FileComparer:
    
    def __init__(self, log_callback=None):
        self.log = log_callback or print
    
    def load_file(self, file_path):
        file_ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if file_ext == '.csv':
                df = self._read_csv_robust(file_path)
            elif file_ext in ['.xlsx', '.xls']:
                df = pd.read_excel(file_path, dtype=str)
            else:
                raise ValueError(f"Unsupported file format: {file_ext}")
            
            self.log(f"📊 Loaded: {os.path.basename(file_path)} - {df.shape[0]} rows × {df.shape[1]} columns")
            self.log(f"📋 Columns: {list(df.columns)}")
            return df
            
        except Exception as e:
            self.log(f"❌ Error loading {file_path}: {e}")
            return None
    
    def _read_csv_robust(self, file_path):
        encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
        delimiters = [',', ';', '\t', '|']
        
        best_df = None
        best_cols = 0
        
        for encoding in encodings:
            for delimiter in delimiters:
                try:
                    df = pd.read_csv(
                        file_path,
                        sep=delimiter,
                        encoding=encoding,
                        dtype=str,
                        on_bad_lines='skip',
                        engine='python'
                    )
                    
                    if df.shape[1] > best_cols:
                        best_cols = df.shape[1]
                        best_df = df
                        
                        if df.shape[1] >= 5:
                            return df
                except:
                    continue
        
        return best_df
    
    def find_column(self, df, possible_names):
        df_columns_lower = {col.lower().strip(): col for col in df.columns}
        
        for name in possible_names:
            name_lower = name.lower().strip()
            if name_lower in df_columns_lower:
                return df_columns_lower[name_lower]
        
        return None
    
    def find_common_columns(self, df1, df2):
        desired_columns = [
            'Title', 'Vulnerability Title', 
            'AssetName', 'Asset Name',
            'DNS', 
            'Asset IPV4', 'IP',
            'Results', 'RESULTS',
            'Solution', 'SOLUTION'
        ]
        
        df1_cols_lower = {col.lower().strip(): col for col in df1.columns}
        df2_cols_lower = {col.lower().strip(): col for col in df2.columns}
        
        common_columns = []
        seen_lower = set()
        
        for col in desired_columns:
            col_lower = col.lower().strip()
            
            if col_lower in seen_lower:
                continue
            
            if col_lower in df1_cols_lower and col_lower in df2_cols_lower:
                common_columns.append(df1_cols_lower[col_lower])
                seen_lower.add(col_lower)
        
        return common_columns
    
    def detect_key_columns(self, df):
        title_options = ['Title', 'Vulnerability Title', 'title', 'TITLE', 'vulnerability title']
        asset_options = ['AssetName', 'Asset Name', 'assetname', 'asset_name', 'Hostname', 'Host']
        dns_options = ['DNS', 'dns', 'DNS Name', 'DNSName', 'FQDN']
        
        title_col = self.find_column(df, title_options)
        asset_col = self.find_column(df, asset_options)
        dns_col = self.find_column(df, dns_options)
        
        if asset_col:
            return title_col, asset_col, "Title + AssetName"
        elif dns_col:
            return title_col, dns_col, "Title + DNS"
        else:
            return title_col, None, None
    
    def _get_columns_to_keep(self, df):
        desired_columns = [
            'Title', 'Vulnerability Title',
            'AssetName', 'Asset Name',
            'DNS',
            'Asset IPV4', 'IP',
            'Results', 'RESULTS',
            'Solution', 'SOLUTION'
        ]
        
        df_columns_lower = {col.lower().strip(): col for col in df.columns}
        columns_to_keep = []
        seen_lower = set()
        
        for col in desired_columns:
            col_lower = col.lower().strip()
            if col_lower in seen_lower:
                continue
            if col_lower in df_columns_lower:
                columns_to_keep.append(df_columns_lower[col_lower])
                seen_lower.add(col_lower)
        
        return columns_to_keep
    
    def _get_columns_to_hide(self, df, columns_to_keep):
        columns_to_hide = [col for col in df.columns if col not in columns_to_keep and col != 'UniqueID']
        return columns_to_hide
    
    def _hide_columns_in_excel(self, file_path, sheet_name, columns, columns_to_hide):
        try:
            wb = load_workbook(file_path)
            ws = wb[sheet_name]
            
            hidden_count = 0
            for col_idx, col_name in enumerate(columns, start=1):
                if col_name in columns_to_hide:
                    col_letter = ws.cell(row=1, column=col_idx).column_letter
                    ws.column_dimensions[col_letter].hidden = True
                    hidden_count += 1
            
            wb.save(file_path)
            self.log(f"🙈 Hidden {hidden_count} columns in sheet '{sheet_name}'")
            
        except Exception as e:
            self.log(f"❌ Error hiding columns in sheet '{sheet_name}': {e}")
    
    def compare_files(self, file1_path, file2_path, output_path):
        self.log(f"🔄 Starting comparison...")
        self.log(f"📁 File 1: {os.path.basename(file1_path)}")
        self.log(f"📁 File 2: {os.path.basename(file2_path)}")
        
        df1 = self.load_file(file1_path)
        df2 = self.load_file(file2_path)
        
        if df1 is None or df2 is None:
            return False, "Failed to load one or both files"
        
        title_col1, second_col1, key_desc1 = self.detect_key_columns(df1)
        if not title_col1 or not second_col1:
            return False, f"Could not find required columns in File 1. Available: {list(df1.columns)}"
        
        self.log(f"✅ File 1 - Using: '{title_col1}' + '{second_col1}'")
        
        title_col2, second_col2, key_desc2 = self.detect_key_columns(df2)
        if not title_col2 or not second_col2:
            return False, f"Could not find required columns in File 2. Available: {list(df2.columns)}"
        
        self.log(f"✅ File 2 - Using: '{title_col2}' + '{second_col2}'")
        
        self.log(f"🔑 Creating UniqueID column...")
        
        df1['UniqueID'] = df1[second_col1].fillna('').astype(str) + ' | ' + df1[title_col1].fillna('').astype(str)
        df2['UniqueID'] = df2[second_col2].fillna('').astype(str) + ' | ' + df2[title_col2].fillna('').astype(str)
        
        keys1 = set(df1['UniqueID'].unique())
        keys2 = set(df2['UniqueID'].unique())
        
        common_keys = keys1.intersection(keys2)
        only_in_file1 = keys1 - keys2
        only_in_file2 = keys2 - keys1
        
        self.log(f"📊 File 1 unique keys: {len(keys1)}")
        self.log(f"📊 File 2 unique keys: {len(keys2)}")
        self.log(f"✅ Matching keys (in both files): {len(common_keys)}")
        self.log(f"📄 Only in File 1: {len(only_in_file1)}")
        self.log(f"📄 Only in File 2: {len(only_in_file2)}")
        
        columns_to_keep_df1 = self._get_columns_to_keep(df1)
        columns_to_keep_df2 = self._get_columns_to_keep(df2)
        
        columns_to_hide_df1 = self._get_columns_to_hide(df1, columns_to_keep_df1)
        columns_to_hide_df2 = self._get_columns_to_hide(df2, columns_to_keep_df2)
        
        self.log(f"📋 File 1 - Keeping visible: {columns_to_keep_df1}")
        self.log(f"📋 File 1 - Will hide: {len(columns_to_hide_df1)} columns")
        self.log(f"📋 File 2 - Keeping visible: {columns_to_keep_df2}")
        self.log(f"📋 File 2 - Will hide: {len(columns_to_hide_df2)} columns")
        
        df1_output_cols = [col for col in df1.columns if col != 'UniqueID']
        df2_output_cols = [col for col in df2.columns if col != 'UniqueID']
        
        matches_df = df1[df1['UniqueID'].isin(common_keys)][df1_output_cols].copy()
        only_file1_df = df1[df1['UniqueID'].isin(only_in_file1)][df1_output_cols].copy()
        only_file2_df = df2[df2['UniqueID'].isin(only_in_file2)][df2_output_cols].copy()
        
        try:
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                matches_df.to_excel(writer, sheet_name='Matching (Both Files)', index=False)
                only_file1_df.to_excel(writer, sheet_name='Only in File 1', index=False)
                only_file2_df.to_excel(writer, sheet_name='Only in File 2', index=False)
                
                summary_data = {
                    'Metric': [
                        'File 1 Total Rows',
                        'File 2 Total Rows',
                        'File 1 Unique Keys',
                        'File 2 Unique Keys',
                        'Matching Keys (Both Files)',
                        'Only in File 1',
                        'Only in File 2',
                        'File 1 Key Columns',
                        'File 2 Key Columns',
                        'Visible Columns (File 1)',
                        'Visible Columns (File 2)'
                    ],
                    'Value': [
                        len(df1),
                        len(df2),
                        len(keys1),
                        len(keys2),
                        len(common_keys),
                        len(only_in_file1),
                        len(only_in_file2),
                        f"{second_col1} + {title_col1}",
                        f"{second_col2} + {title_col2}",
                        ', '.join(columns_to_keep_df1),
                        ', '.join(columns_to_keep_df2)
                    ]
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            self._hide_columns_in_excel(output_path, 'Matching (Both Files)', df1_output_cols, columns_to_hide_df1)
            self._hide_columns_in_excel(output_path, 'Only in File 1', df1_output_cols, columns_to_hide_df1)
            self._hide_columns_in_excel(output_path, 'Only in File 2', df2_output_cols, columns_to_hide_df2)
            
            self.log(f"💾 Saved comparison results to: {output_path}")
            self.log(f"📋 Sheets: 'Matching (Both Files)', 'Only in File 1', 'Only in File 2', 'Summary'")
            self.log(f"📋 Columns are hidden, not deleted - all data is preserved")
            
            return True, output_path
            
        except Exception as e:
            self.log(f"❌ Error saving results: {e}")
            import traceback
            self.log(traceback.format_exc())
            return False, str(e)


class WizParser:
    """Parse Wiz JSON response and extract SECURITY_TOOL_FINDING entities."""

    def __init__(self, input_path, output_path, log_callback=None):
        self.input_path = input_path
        self.output_path = output_path
        self.log = log_callback or print

    def parse_wiz_response(self, data):
        """Extract SECURITY_TOOL_FINDING entities from issuesV2 response.

        Every field access is null-safe: the Wiz GraphQL API can return
        explicit null for sourceRules, cloudAccounts, entity,
        evidenceQueryResults, properties, etc.  Using ``or`` instead of
        .get(key, default) catches both missing keys *and* null values.
        """
        rows = []

        nodes = (data.get("data") or {}).get("issuesV2") or {}
        nodes = nodes.get("nodes") or []
        if not nodes:
            self.log("⚠️ No issue nodes found in the response.")
            return rows

        for issue in nodes:
            # Issue-level info — any of these can be None, not just missing
            source_rules = issue.get("sourceRules") or [{}]
            rule = source_rules[0].get("name", "N/A") if source_rules else "N/A"

            cloud_accounts = issue.get("cloudAccounts") or [{}]
            first_account = cloud_accounts[0] if cloud_accounts else {}
            first_account = first_account or {}
            account_name = first_account.get("name", "N/A")
            account_id = first_account.get("externalId", "N/A")

            entity_info = issue.get("entity") or {}
            asset_name = entity_info.get("name", "N/A")
            asset_type = entity_info.get("type", "N/A")

            # Evidence entities
            evidence_results = issue.get("evidenceQueryResults") or {}
            evidence_nodes = evidence_results.get("nodes") or []
            for ev_node in evidence_nodes:
                entities = ev_node.get("entities") or []
                for entity in entities:
                    if entity and entity.get("type") == "SECURITY_TOOL_FINDING":
                        props = entity.get("properties") or {}
                        rows.append({
                            "Rule": rule,
                            "Asset": asset_name,
                            "Account Name": account_name,
                            "Subscription ID": account_id,
                            "CVE": entity.get("name", "N/A"),
                            "Description": props.get("description", props.get("CVEDescription", "N/A")),
                        })

        return rows

    def run(self):
        try:
            self.log(f"📂 Loading JSON: {os.path.basename(self.input_path)}")

            with open(self.input_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.log(f"✅ JSON loaded successfully")

            rows = self.parse_wiz_response(data)

            if not rows:
                self.log("⚠️ No SECURITY_TOOL_FINDING entities found in the JSON.")
                return False, "No SECURITY_TOOL_FINDING entities found"

            self.log(f"🔍 Found {len(rows)} findings, writing to CSV...")

            fieldnames = ["Rule", "Asset", "Account Name",
                          "Subscription ID", "CVE", "Description"]

            with open(self.output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            unique_cves = set(r["CVE"] for r in rows)
            unique_assets = set(r["Asset"] for r in rows)
            unique_rules = set(r["Rule"] for r in rows)

            self.log(f"📊 Summary:")
            self.log(f"   • {len(rows)} total findings")
            self.log(f"   • {len(unique_cves)} unique CVEs")
            self.log(f"   • {len(unique_assets)} unique assets")
            self.log(f"   • {len(unique_rules)} unique issue rules")
            self.log(f"💾 Saved to: {self.output_path}")

            return True, self.output_path

        except json.JSONDecodeError as e:
            self.log(f"❌ Invalid JSON file: {e}")
            return False, f"Invalid JSON: {e}"
        except Exception as e:
            self.log(f"❌ Error: {e}")
            import traceback
            self.log(traceback.format_exc())
            return False, str(e)


# ---------------------------------------------------------------------------
#  BU Grouper – looks up each DNS in bu_database.json, splits into sheets
# ---------------------------------------------------------------------------
class BUGrouper:
    """Group assets by Business Unit using the local JSON database."""

    def __init__(self, log_callback=None):
        self.log = log_callback or print
        self.db = None
        self.meta = None

    # -- database helpers ---------------------------------------------------

    @staticmethod
    def db_exists():
        """Check whether bu_database.json is present next to the script."""
        return os.path.isfile(BU_DB_PATH)

    @staticmethod
    def load_db_meta():
        """Return just the _meta block (cheap check for the UI status label)."""
        if not os.path.isfile(BU_DB_PATH):
            return None
        try:
            with open(BU_DB_PATH, "r", encoding="utf-8") as f:
                db = json.load(f)
            return db.get("_meta")
        except Exception:
            return None

    def load_db(self):
        if not os.path.isfile(BU_DB_PATH):
            self.log(f"❌ BU database not found at: {BU_DB_PATH}")
            self.log(f"   Use 'Rebuild Database' in the Group by BU tab first.")
            return False

        try:
            with open(BU_DB_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)

            self.meta = raw.get("_meta", {})
            self.db = raw.get("assets", {})

            self.log(f"✅ Loaded BU database: {self.meta.get('total_assets', '?')} assets, "
                     f"{len(self.meta.get('business_units', []))} BUs")
            self.log(f"   Source: {self.meta.get('source_file', 'unknown')}  |  "
                     f"Generated: {self.meta.get('generated_at', 'unknown')}")
            return True

        except Exception as e:
            self.log(f"❌ Failed to load BU database: {e}")
            return False

    # -- build database from master Excel -----------------------------------

    def build_database(self, master_path):
        """Read a master Excel (one sheet per BU, DNS in col A), write bu_database.json."""

        if not os.path.exists(master_path):
            self.log(f"❌ File not found: {master_path}")
            return False, "File not found"

        self.log(f"📂 Loading master file: {os.path.basename(master_path)}")

        try:
            xl = pd.ExcelFile(master_path)
        except Exception as e:
            self.log(f"❌ Cannot open Excel file: {e}")
            return False, str(e)

        sheet_names = xl.sheet_names
        self.log(f"📋 Found {len(sheet_names)} sheets (Business Units): {sheet_names}")

        assets = {}
        duplicates = []
        stats = {}

        for sheet_name in sheet_names:
            bu_name = sheet_name.strip()
            df = xl.parse(sheet_name, dtype=str)

            # Find the DNS column (case-insensitive)
            dns_col = None
            for col in df.columns:
                if col.strip().lower() == "dns":
                    dns_col = col
                    break

            if dns_col is None:
                if len(df.columns) > 0:
                    dns_col = df.columns[0]
                    self.log(f"⚠️  Sheet '{bu_name}': No 'DNS' header found, using first column '{dns_col}'")
                else:
                    self.log(f"⚠️  Sheet '{bu_name}': Empty sheet, skipping")
                    stats[bu_name] = 0
                    continue

            count = 0
            for _, row in df.iterrows():
                raw_value = row[dns_col]
                if pd.isna(raw_value) or str(raw_value).strip() == "":
                    continue

                hostname = str(raw_value).strip().lower()

                if hostname in assets:
                    existing_bu = assets[hostname]
                    duplicates.append({
                        "hostname": hostname,
                        "bu_1": existing_bu,
                        "bu_2": bu_name,
                    })
                    self.log(f"⚠️  DUPLICATE: '{hostname}' found in both '{existing_bu}' and '{bu_name}'")
                else:
                    assets[hostname] = bu_name
                    count += 1

            stats[bu_name] = count
            self.log(f"   ✅ {bu_name}: {count} assets")

        # Summary
        self.log(f"\n📊 Summary: {len(assets)} unique assets across {len(sheet_names)} Business Units")

        if duplicates:
            self.log(f"⚠️  {len(duplicates)} DUPLICATE(S) DETECTED (first occurrence kept):")
            for dup in duplicates:
                self.log(f"   - {dup['hostname']}: '{dup['bu_1']}' vs '{dup['bu_2']}'")

        # Build output
        db = {
            "_meta": {
                "generated_at": datetime.now().astimezone().isoformat(),
                "source_file": os.path.basename(master_path),
                "total_assets": len(assets),
                "business_units": sorted(stats.keys()),
                "assets_per_bu": stats,
                "duplicates_found": len(duplicates),
            },
            "assets": assets,
        }

        try:
            with open(BU_DB_PATH, "w", encoding="utf-8") as f:
                json.dump(db, f, indent=2, ensure_ascii=False)

            self.log(f"\n💾 Database saved to: {BU_DB_PATH}")
            self.log(f"   {len(assets)} assets, {len(sheet_names)} BUs")

            if duplicates:
                self.log(f"\n⚠️  Review the duplicates above and fix them in the master file.")

            return True, BU_DB_PATH

        except Exception as e:
            self.log(f"❌ Error saving database: {e}")
            return False, str(e)

    # -- formatting rule detection ------------------------------------------

    def _detect_columns_to_keep(self, df):
        """Thin wrapper over the shared rule table (see detect_columns_to_keep).

        The 'Business Unit' column this class appends is excluded from
        detection so it can never be mistaken for a source column.
        """
        source_columns = [c for c in df.columns if c != "Business Unit"]
        rule, columns_to_keep = detect_columns_to_keep(source_columns)

        if rule:
            self.log(f"🔍 Detected '{rule}' format")
        else:
            first_col = str(source_columns[0]).strip() if source_columns else ""
            self.log(f"ℹ️ No formatting rule matched for first column '{first_col}'")

        return columns_to_keep

    # -- core logic ---------------------------------------------------------

    def group_file(self, input_path, output_path):
        """Read a formatted Excel/CSV, group rows by BU, write output."""

        # 1. Load DB
        if not self.load_db():
            return False, "BU database not loaded"

        # 2. Load input file
        file_ext = os.path.splitext(input_path)[1].lower()
        try:
            if file_ext == '.csv':
                df = pd.read_csv(input_path, dtype=str)
            elif file_ext in ['.xlsx', '.xls']:
                df = pd.read_excel(input_path, dtype=str)
            else:
                return False, f"Unsupported format: {file_ext}"
        except Exception as e:
            self.log(f"❌ Error loading input file: {e}")
            return False, str(e)

        self.log(f"📊 Loaded input: {os.path.basename(input_path)} — "
                 f"{df.shape[0]} rows × {df.shape[1]} columns")

        # 3. Find the asset/host column (case-insensitive, first match wins)
        asset_col_options = ["dns", "asset name", "assetname", "resource name"]
        dns_col = None
        for col in df.columns:
            if col.strip().lower() in asset_col_options:
                dns_col = col
                break

        if dns_col is None:
            self.log(f"❌ No matching column found. Looking for: {asset_col_options}")
            self.log(f"   Available columns: {list(df.columns)}")
            return False, "No DNS / Asset Name / Resource Name column in input file"

        self.log(f"🔑 Using column '{dns_col}' for BU lookup")

        # 4. Look up each row
        bu_column = []
        matched = 0
        unmatched = 0

        for _, row in df.iterrows():
            raw = row[dns_col]
            if pd.isna(raw) or str(raw).strip() == "":
                bu_column.append("_Unmapped")
                unmatched += 1
                continue

            hostname = str(raw).strip().lower()
            bu = self.db.get(hostname)

            if bu:
                bu_column.append(bu)
                matched += 1
            else:
                bu_column.append("_Unmapped")
                unmatched += 1

        df["Business Unit"] = bu_column

        self.log(f"✅ Lookup complete: {matched} matched, {unmatched} unmapped")

        # 5. Detect which columns to keep/hide (shared rules with Format tab)
        columns_to_keep = self._detect_columns_to_keep(df)
        columns_to_hide = [col for col in df.columns
                           if col not in columns_to_keep and col != "Business Unit"]

        if columns_to_keep:
            self.log(f"📋 Visible columns: {columns_to_keep}")
            self.log(f"🙈 Will hide {len(columns_to_hide)} columns per sheet")
        else:
            self.log(f"ℹ️ No formatting rule matched — all columns stay visible")
            columns_to_hide = []

        # 6. Split into sheets per BU
        bu_groups = {}
        for bu_name in sorted(df["Business Unit"].unique()):
            bu_df = df[df["Business Unit"] == bu_name].copy()
            bu_df = bu_df.drop(columns=["Business Unit"])
            bu_groups[bu_name] = bu_df

        # 7. Write output
        try:
            with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
                for bu_name, bu_df in bu_groups.items():
                    safe_name = bu_name[:31]
                    bu_df.to_excel(writer, sheet_name=safe_name, index=False)
                    self.log(f"   📄 {safe_name}: {len(bu_df)} rows")

                # Summary sheet
                summary_rows = []
                for bu_name, bu_df in bu_groups.items():
                    summary_rows.append({
                        "Business Unit": bu_name,
                        "Asset Count": len(bu_df),
                    })
                summary_df = pd.DataFrame(summary_rows)
                summary_df.loc[len(summary_df)] = {
                    "Business Unit": "TOTAL",
                    "Asset Count": len(df),
                }
                summary_df.to_excel(writer, sheet_name="Summary", index=False)

            # 8. Hide columns in each BU sheet (not Summary)
            if columns_to_hide:
                wb = load_workbook(output_path)
                total_hidden = 0
                sheets_touched = 0

                for bu_name, bu_df in bu_groups.items():
                    safe_name = bu_name[:31]
                    ws = wb[safe_name]
                    sheet_hidden = 0

                    # Columns as written, in the same order as the DataFrame
                    for col_idx, col_name in enumerate(bu_df.columns, start=1):
                        if col_name in columns_to_hide:
                            col_letter = ws.cell(row=1, column=col_idx).column_letter
                            ws.column_dimensions[col_letter].hidden = True
                            sheet_hidden += 1

                    if sheet_hidden:
                        sheets_touched += 1
                        total_hidden += sheet_hidden

                wb.save(output_path)

                if total_hidden:
                    self.log(f"🙈 Hidden {total_hidden} column(s) across "
                             f"{sheets_touched} sheet(s)")
                else:
                    self.log(f"ℹ️ Nothing to hide — none of the {len(columns_to_hide)} "
                             f"flagged columns are present in the output sheets")

            self.log(f"\n💾 Saved to: {output_path}")
            self.log(f"📋 {len(bu_groups)} sheets + Summary")
            return True, output_path

        except Exception as e:
            self.log(f"❌ Error writing output: {e}")
            import traceback
            self.log(traceback.format_exc())
            return False, str(e)


# ---------------------------------------------------------------------------
#  Qualys report API client
# ---------------------------------------------------------------------------
class QualysClient:
    """Minimal Qualys VM/PC report API client (stdlib only).

    The List Reports endpoint cannot filter by title or launch date, so we pull
    the full list (optionally narrowed by state) and filter client-side for
    titles containing a keyword and launched in a given month.
    """

    REPORT_PATH = "/api/3.0/fo/report/"
    _EXT_BY_FORMAT = {
        "CSV": ".csv",
        "XML": ".xml",
        "PDF": ".pdf",
        "MHT": ".mht",
        "HTML": ".html",
        "DOCX": ".docx",
        "XLSX": ".xlsx",
    }

    def __init__(self, base_url, username, password_provider, log_callback=None):
        if not base_url or not username:
            raise VaultNotConfigured(
                "Qualys connection not configured: "
                + ", ".join(qualys_config_problems())
            )
        self.base_url = base_url.rstrip("/")
        self.username = username
        # password_provider is a callable so the plaintext is only materialised
        # at the moment a request is sent, never stored on the instance.
        self.password_provider = password_provider
        self.log = log_callback or print

    def _send(self, path, params=None, method="POST"):
        url = self.base_url + path
        data = None
        if params is not None:
            data = urllib.parse.urlencode(params).encode("utf-8")
        elif method == "POST":
            data = b""
        req = urllib.request.Request(url, data=data, method=method)

        # Decrypt the password only here, build the header, then let it go.
        password = self.password_provider()
        token = base64.b64encode(f"{self.username}:{password}".encode("utf-8")).decode("ascii")
        req.add_header("Authorization", "Basic " + token)
        del password, token
        # Qualys requires this header on every API call.
        req.add_header("X-Requested-With", APP_NAME)

        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=180) as resp:
                return resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Qualys API HTTP {e.code}: {body[:500]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Qualys API connection error: {e.reason}") from e

    def _request(self, params):
        return self._send(self.REPORT_PATH, params, method="POST")

    @staticmethod
    def _text(elem):
        return elem.text.strip() if elem is not None and elem.text else ""

    @staticmethod
    def is_registration_error(message):
        """Detect the 'account not activated / EULA not accepted' family of errors."""
        msg = (message or "").lower()
        needles = ("2003", "registration", "eula", "access denied",
                   "not activated", "pending activation", "first login")
        return any(n in msg for n in needles)

    def accept_eula(self):
        """Complete first-login registration by accepting the Qualys EULA.

        Required for API-only accounts (no GUI login). Only needs to succeed
        once; afterwards normal API calls work.
        """
        self.log("📝 Accepting Qualys EULA (/msp/acceptEULA.php) to activate the account...")
        body, _ = self._send("/msp/acceptEULA.php", method="GET")
        text = body.decode("utf-8", errors="replace")

        status, msg = None, text.strip()[:300]
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(body)
            ret = root.find(".//RETURN")
            if ret is not None:
                status = ret.get("status")
                msg = (ret.text or "").strip() or msg
        except Exception:
            pass

        if status == "SUCCESS" or "accepted" in text.lower():
            self.log(f"✅ EULA accepted / account activated: {msg}")
            return True

        self.log(f"⚠️ EULA acceptance did not confirm success: {msg}")
        return False

    def list_reports(self, state="Finished"):
        """Return a list of report dicts (id, title, launch, fmt, state)."""
        import xml.etree.ElementTree as ET

        params = {"action": "list"}
        if state and state.lower() != "all":
            params["state"] = state

        self.log(f"🌐 Requesting report list from {self.base_url} (state={state})...")
        body, _ = self._request(params)

        try:
            root = ET.fromstring(body)
        except ET.ParseError as e:
            raise RuntimeError(f"Could not parse report list XML: {e}") from e

        # Surface API-level errors returned as SIMPLE_RETURN.
        text_node = root.find(".//RESPONSE/TEXT")
        if root.tag == "SIMPLE_RETURN" and text_node is not None:
            raise RuntimeError(f"Qualys API error: {self._text(text_node)}")

        reports = []
        for rep in root.findall(".//REPORT"):
            reports.append({
                "id": self._text(rep.find("ID")),
                "title": self._text(rep.find("TITLE")),
                "launch": self._text(rep.find("LAUNCH_DATETIME")),
                "fmt": self._text(rep.find("OUTPUT_FORMAT")).upper(),
                "state": self._text(rep.find("STATUS/STATE")),
            })

        self.log(f"📋 Report list returned {len(reports)} report(s)")
        return reports

    @staticmethod
    def _parse_launch(value):
        if not value:
            return None
        value = value.strip()
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        # Last resort: take just the date part.
        try:
            return datetime.strptime(value[:10], "%Y-%m-%d")
        except ValueError:
            return None

    def filter_reports(self, reports, title_contains="PCI", current_month_only=True,
                       year=None, month=None, only_csv=True):
        """Filter for titles containing a keyword, (optionally) a given month,
        and (optionally) CSV output format only."""
        now = datetime.now()
        year = year or now.year
        month = month or now.month
        keyword = (title_contains or "").lower()

        matches = []
        skipped_non_csv = 0
        for r in reports:
            if keyword and keyword not in r["title"].lower():
                continue
            if current_month_only:
                dt = self._parse_launch(r["launch"])
                if dt is None or dt.year != year or dt.month != month:
                    continue
            if only_csv and r.get("fmt", "") != "CSV":
                skipped_non_csv += 1
                continue
            matches.append(r)

        scope = f"{year}-{month:02d}" if current_month_only else "any month"
        fmt_note = " CSV-only," if only_csv else ""
        self.log(f"🔎 {len(matches)}{fmt_note} report(s) match title~'{title_contains}' / {scope}")
        if only_csv and skipped_non_csv:
            self.log(f"⏭️ Skipped {skipped_non_csv} matching report(s) that were not CSV format")
        for r in matches:
            self.log(f"   • [{r['id']}] {r['title']} (launched {r['launch']}, {r['fmt'] or '?'})")
        return matches

    @staticmethod
    def _safe_name(name):
        cleaned = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip().strip(".")
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned[:120] or "report"

    def fetch_report(self, report, output_dir):
        """Download a single report's content to output_dir; return the path."""
        report_id = report["id"]
        self.log(f"⬇️ Fetching report id={report_id} ...")
        body, headers = self._request({"action": "fetch", "id": report_id})

        # If Qualys returns an XML error instead of the file, detect it.
        head = body[:200].lstrip()
        if head.startswith(b"<?xml") and b"SIMPLE_RETURN" in body[:400]:
            try:
                import xml.etree.ElementTree as ET
                node = ET.fromstring(body).find(".//RESPONSE/TEXT")
                msg = self._text(node) if node is not None else "unknown error"
            except Exception:
                msg = "unknown error"
            raise RuntimeError(f"Fetch failed for report {report_id}: {msg}")

        ext = self._EXT_BY_FORMAT.get(report.get("fmt", ""), "")
        if not ext:
            ctype = headers.get("Content-Type", "").lower()
            if "csv" in ctype:
                ext = ".csv"
            elif "spreadsheet" in ctype or "xlsx" in ctype:
                ext = ".xlsx"
            elif "pdf" in ctype:
                ext = ".pdf"
            elif "xml" in ctype:
                ext = ".xml"
            else:
                ext = ".csv"

        filename = f"{self._safe_name(report['title'])}_{report_id}{ext}"
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, filename)
        with open(path, "wb") as f:
            f.write(body)
        self.log(f"💾 Saved raw report: {filename} ({len(body)} bytes)")
        return path


# ---------------------------------------------------------------------------
#  Worker threads
# ---------------------------------------------------------------------------
class FormatterThread(QThread):
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    
    def __init__(self, input_path, output_path):
        super().__init__()
        self.input_path = input_path
        self.output_path = output_path
    
    def run(self):
        self.progress.emit(10)
        formatter = FileFormatter(self.input_path, self.log_message.emit)
        
        self.progress.emit(30)
        if not formatter.load_file():
            self.finished_signal.emit(False, "Failed to load file")
            return
        
        self.progress.emit(50)
        formatter.apply_formatting_rules()
        
        self.progress.emit(70)
        info = formatter.get_info()
        self.log_message.emit(f"📊 Data shape: {info['shape'][0]} rows × {info['shape'][1]} columns")
        
        self.progress.emit(90)
        result = formatter.save_file(self.output_path)
        
        self.progress.emit(100)
        if result:
            self.finished_signal.emit(True, self.output_path)
        else:
            self.finished_signal.emit(False, "Failed to save file")


class ComparerThread(QThread):
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    
    def __init__(self, file1_path, file2_path, output_path):
        super().__init__()
        self.file1_path = file1_path
        self.file2_path = file2_path
        self.output_path = output_path
    
    def run(self):
        self.progress.emit(10)
        comparer = FileComparer(self.log_message.emit)
        
        self.progress.emit(30)
        success, result = comparer.compare_files(
            self.file1_path,
            self.file2_path,
            self.output_path
        )
        
        self.progress.emit(100)
        self.finished_signal.emit(success, result)


class WizThread(QThread):
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, input_path, output_path):
        super().__init__()
        self.input_path = input_path
        self.output_path = output_path

    def run(self):
        self.progress.emit(10)
        parser = WizParser(self.input_path, self.output_path, self.log_message.emit)

        self.progress.emit(30)
        success, result = parser.run()

        self.progress.emit(100)
        self.finished_signal.emit(success, result)


class BUGrouperThread(QThread):
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, input_path, output_path):
        super().__init__()
        self.input_path = input_path
        self.output_path = output_path

    def run(self):
        self.progress.emit(10)
        grouper = BUGrouper(self.log_message.emit)

        self.progress.emit(30)
        success, result = grouper.group_file(self.input_path, self.output_path)

        self.progress.emit(100)
        self.finished_signal.emit(success, result)


class BUBuilderThread(QThread):
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, master_path):
        super().__init__()
        self.master_path = master_path

    def run(self):
        self.progress.emit(10)
        grouper = BUGrouper(self.log_message.emit)

        self.progress.emit(30)
        success, result = grouper.build_database(self.master_path)

        self.progress.emit(100)
        self.finished_signal.emit(success, result)


class QualysThread(QThread):
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, output_dir, title_contains="PCI", state="Finished",
                 current_month_only=True, apply_formatting=True):
        super().__init__()
        self.output_dir = output_dir
        self.title_contains = title_contains
        self.state = state
        self.current_month_only = current_month_only
        self.apply_formatting = apply_formatting

    def run(self):
        log = self.log_message.emit
        try:
            self.progress.emit(5)
            client = QualysClient(
                get_qualys_api_url(),
                get_qualys_api_user(),
                get_qualys_password,
                log,
            )

            self.progress.emit(15)
            try:
                reports = client.list_reports(self.state)
            except RuntimeError as e:
                if QualysClient.is_registration_error(str(e)):
                    log("ℹ️ Account appears unactivated (EULA not accepted). "
                        "Attempting one-time activation...")
                    if client.accept_eula():
                        reports = client.list_reports(self.state)
                    else:
                        raise
                else:
                    raise

            self.progress.emit(35)
            matches = client.filter_reports(
                reports,
                title_contains=self.title_contains,
                current_month_only=self.current_month_only,
            )

            if not matches:
                self.progress.emit(100)
                self.finished_signal.emit(
                    False,
                    f"No reports matched title~'{self.title_contains}'"
                    + (" for the current month." if self.current_month_only else "."),
                )
                return

            total = len(matches)
            formatted_count = 0

            for i, report in enumerate(matches):
                self.progress.emit(35 + int(55 * i / total))

                raw_path = client.fetch_report(report, self.output_dir)

                ext = os.path.splitext(raw_path)[1].lower()
                if self.apply_formatting and ext in (".csv", ".xlsx", ".xls"):
                    log(f"🛠️ Applying formatting rules to {os.path.basename(raw_path)} ...")
                    formatter = FileFormatter(raw_path, log)
                    if formatter.load_file():
                        formatter.apply_formatting_rules()
                        out_base = os.path.splitext(formatter.file_path)[0]
                        out_path = f"{out_base}_formatted.xlsx"
                        if formatter.save_file(out_path):
                            formatted_count += 1
                    else:
                        log(f"⚠️ Could not load {os.path.basename(raw_path)} for formatting")
                elif self.apply_formatting:
                    log(f"ℹ️ Skipping formatting for {os.path.basename(raw_path)} "
                        f"(unsupported format '{ext}')")

            self.progress.emit(100)
            summary = (f"Downloaded {total} report(s); formatted {formatted_count}. "
                       f"Saved to: {self.output_dir}")
            log(f"📂 Files saved in: {self.output_dir}")
            self.finished_signal.emit(True, summary)

        except VaultNotConfigured as e:
            log(f"🔑 Credential vault not ready: {e}")
            self.progress.emit(100)
            self.finished_signal.emit(False, str(e))

        except Exception as e:
            import traceback
            log(f"❌ Qualys error: {e}")
            log(traceback.format_exc())
            self.progress.emit(100)
            self.finished_signal.emit(False, str(e))


class QualysEulaThread(QThread):
    log_message = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def run(self):
        log = self.log_message.emit
        try:
            client = QualysClient(
                get_qualys_api_url(), get_qualys_api_user(), get_qualys_password, log
            )
            ok = client.accept_eula()
            self.finished_signal.emit(
                ok,
                "EULA accepted — account activated." if ok
                else "EULA acceptance could not be confirmed.",
            )
        except VaultNotConfigured as e:
            log(f"🔑 Credential vault not ready: {e}")
            self.finished_signal.emit(False, str(e))
        except Exception as e:
            import traceback
            log(f"❌ EULA acceptance error: {e}")
            log(traceback.format_exc())
            self.finished_signal.emit(False, str(e))


# ---------------------------------------------------------------------------
#  Reusable UI widgets
# ---------------------------------------------------------------------------
class ModernButton(QPushButton):
    
    def __init__(self, text, primary=False, parent=None):
        super().__init__(text, parent)
        self.primary = primary
        self.setup_style()
        
    def setup_style(self):
        if self.primary:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #2563eb;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    padding: 12px 24px;
                    font-size: 14px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background-color: #1d4ed8;
                }
                QPushButton:pressed {
                    background-color: #1e40af;
                }
                QPushButton:disabled {
                    background-color: #94a3b8;
                }
            """)
        else:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #f1f5f9;
                    color: #334155;
                    border: 1px solid #e2e8f0;
                    border-radius: 8px;
                    padding: 12px 24px;
                    font-size: 14px;
                    font-weight: 500;
                }
                QPushButton:hover {
                    background-color: #e2e8f0;
                    border-color: #cbd5e1;
                }
                QPushButton:pressed {
                    background-color: #cbd5e1;
                }
            """)


class FileInputWidget(QFrame):
    
    def __init__(self, label_text, placeholder, is_save=False, file_filter=None,
                 is_dir=False, parent=None):
        super().__init__(parent)
        self.is_save = is_save
        self.is_dir = is_dir
        self.label_text = label_text
        self.placeholder = placeholder
        self.file_filter = file_filter
        self.setup_ui()
        
    def setup_ui(self):
        self.setStyleSheet("QFrame { background-color: transparent; }")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        label = QLabel(self.label_text)
        label.setStyleSheet("QLabel { color: #374151; font-size: 13px; font-weight: 600; }")
        layout.addWidget(label)
        
        input_layout = QHBoxLayout()
        input_layout.setSpacing(8)
        
        self.line_edit = QLineEdit()
        self.line_edit.setPlaceholderText(self.placeholder)
        self.line_edit.setStyleSheet("""
            QLineEdit {
                background-color: #ffffff;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                padding: 10px 14px;
                font-size: 13px;
                color: #1f2937;
            }
            QLineEdit:focus {
                border-color: #2563eb;
            }
        """)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #374151;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 16px;
                font-size: 13px;
                font-weight: 500;
            }
            QPushButton:hover {
                background-color: #1f2937;
            }
        """)
        browse_btn.clicked.connect(self.browse_file)
        
        input_layout.addWidget(self.line_edit, 1)
        input_layout.addWidget(browse_btn)
        
        layout.addLayout(input_layout)
    
    def browse_file(self):
        default_filter = self.file_filter or "Excel/CSV Files (*.xlsx *.xls *.csv);;All Files (*)"
        
        if self.is_dir:
            folder = QFileDialog.getExistingDirectory(self, "Select Folder", "")
            if folder:
                self.line_edit.setText(folder)
            return
        
        if self.is_save:
            save_filter = self.file_filter or "Excel Files (*.xlsx);;CSV Files (*.csv);;All Files (*)"
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save File", "", save_filter
            )
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select File", "", default_filter
            )
        
        if file_path:
            self.line_edit.setText(file_path)
            
            if not self.is_save and hasattr(self, 'output_widget'):
                base, ext = os.path.splitext(file_path)
                if hasattr(self, 'output_suffix'):
                    suggested_output = f"{base}{self.output_suffix}"
                else:
                    suggested_output = f"{base}_formatted.xlsx"
                self.output_widget.line_edit.setText(suggested_output)
    
    def get_path(self):
        return self.line_edit.text()
    
    def set_output_widget(self, widget, suffix="_formatted.xlsx"):
        self.output_widget = widget
        self.output_suffix = suffix


# ---------------------------------------------------------------------------
#  Main Window
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(800, 750)
        self.setup_ui()
        
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        central.setStyleSheet("background-color: #f8fafc;")
        
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(20)
        
        # Header
        header = QFrame()
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(4)
        
        title = QLabel(f"📁 {APP_NAME}")
        title.setStyleSheet("color: #111827; font-size: 28px; font-weight: 700;")
        
        subtitle = QLabel("Automatically format and clean your Excel and CSV files")
        subtitle.setStyleSheet("color: #6b7280; font-size: 14px;")
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        main_layout.addWidget(header)
        
        # Tab Widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #e5e7eb;
                border-radius: 12px;
                background-color: #ffffff;
                padding: 20px;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #e2e8f0;
                color: #64748b;
                border: 1px solid #e2e8f0;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                padding: 12px 28px;
                margin-right: 4px;
                font-weight: 600;
                font-size: 13px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                color: #2563eb;
                border-color: #e5e7eb;
            }
            QTabBar::tab:hover:!selected {
                background-color: #cbd5e1;
            }
        """)
        
        # ===== FORMAT TAB =====
        format_tab = QWidget()
        format_layout = QVBoxLayout(format_tab)
        format_layout.setContentsMargins(0, 10, 0, 0)
        format_layout.setSpacing(16)
        
        self.input_widget = FileInputWidget("Input File", "Select a CSV or Excel file to format...")
        self.output_widget = FileInputWidget("Output File", "Choose where to save the formatted file...", is_save=True)
        self.input_widget.set_output_widget(self.output_widget)
        
        format_layout.addWidget(self.input_widget)
        format_layout.addWidget(self.output_widget)
        
        self.format_progress_bar = QProgressBar()
        self.format_progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #e5e7eb;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #2563eb;
                border-radius: 4px;
            }
        """)
        self.format_progress_bar.setTextVisible(False)
        self.format_progress_bar.setValue(0)
        self.format_progress_bar.setVisible(False)
        format_layout.addWidget(self.format_progress_bar)
        
        self.format_btn = ModernButton("Format File", primary=True)
        self.format_btn.setMinimumHeight(48)
        self.format_btn.clicked.connect(self.start_formatting)
        format_layout.addWidget(self.format_btn)
        
        format_layout.addStretch()
        self.tab_widget.addTab(format_tab, "📁 Format File")
        
        # ===== COMPARE TAB =====
        compare_tab = QWidget()
        compare_layout = QVBoxLayout(compare_tab)
        compare_layout.setContentsMargins(0, 10, 0, 0)
        compare_layout.setSpacing(16)
        
        self.compare_file1_widget = FileInputWidget("File 1 (Base File)", "Select the first CSV or Excel file...")
        self.compare_file2_widget = FileInputWidget("File 2 (Compare With)", "Select the second CSV or Excel file...")
        
        compare_layout.addWidget(self.compare_file1_widget)
        compare_layout.addWidget(self.compare_file2_widget)
        
        self.key_type_combo = QComboBox()
        self.key_type_combo.addItem("Title + AssetName", "title_asset")
        self.key_type_combo.addItem("Title + DNS", "title_dns")
        self.key_type_combo.setStyleSheet("""
            QComboBox {
                background-color: #ffffff;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                padding: 10px 14px;
                font-size: 13px;
                color: #1f2937;
            }
            QComboBox:focus {
                border-color: #2563eb;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 10px;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                border: 1px solid #d1d5db;
                selection-background-color: #2563eb;
                selection-color: white;
            }
        """)
        
        self.compare_output_widget = FileInputWidget("Output File", "Choose where to save the comparison results...", is_save=True)
        compare_layout.addWidget(self.compare_output_widget)
        
        self.compare_progress_bar = QProgressBar()
        self.compare_progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #e5e7eb;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #2563eb;
                border-radius: 4px;
            }
        """)
        self.compare_progress_bar.setTextVisible(False)
        self.compare_progress_bar.setValue(0)
        self.compare_progress_bar.setVisible(False)
        compare_layout.addWidget(self.compare_progress_bar)
        
        self.compare_btn = ModernButton("Compare Files", primary=True)
        self.compare_btn.setMinimumHeight(48)
        self.compare_btn.clicked.connect(self.start_comparison)
        compare_layout.addWidget(self.compare_btn)
        
        compare_layout.addStretch()
        self.tab_widget.addTab(compare_tab, "🔍 Compare Files")
        
        # ===== WIZ TAB =====
        wiz_tab = QWidget()
        wiz_layout = QVBoxLayout(wiz_tab)
        wiz_layout.setContentsMargins(0, 10, 0, 0)
        wiz_layout.setSpacing(16)

        self.wiz_input_widget = FileInputWidget(
            "Input File (Wiz JSON)",
            "Select a Wiz response JSON file...",
            file_filter="JSON Files (*.json);;All Files (*)"
        )
        self.wiz_output_widget = FileInputWidget(
            "Output File (CSV)",
            "Choose where to save the CVE findings CSV...",
            is_save=True,
            file_filter="CSV Files (*.csv);;All Files (*)"
        )
        self.wiz_input_widget.set_output_widget(self.wiz_output_widget, suffix="_cve_findings.csv")

        wiz_layout.addWidget(self.wiz_input_widget)
        wiz_layout.addWidget(self.wiz_output_widget)

        self.wiz_progress_bar = QProgressBar()
        self.wiz_progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #e5e7eb;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #2563eb;
                border-radius: 4px;
            }
        """)
        self.wiz_progress_bar.setTextVisible(False)
        self.wiz_progress_bar.setValue(0)
        self.wiz_progress_bar.setVisible(False)
        wiz_layout.addWidget(self.wiz_progress_bar)

        self.wiz_btn = ModernButton("Parse Wiz JSON", primary=True)
        self.wiz_btn.setMinimumHeight(48)
        self.wiz_btn.clicked.connect(self.start_wiz_parsing)
        wiz_layout.addWidget(self.wiz_btn)

        wiz_layout.addStretch()
        self.tab_widget.addTab(wiz_tab, "🛡️ Wiz")

        # ===== GROUP BY BU TAB =====
        bu_tab = QWidget()
        bu_layout = QVBoxLayout(bu_tab)
        bu_layout.setContentsMargins(0, 10, 0, 0)
        bu_layout.setSpacing(16)

        # DB status banner
        self.bu_db_status = QLabel()
        self.bu_db_status.setWordWrap(True)
        self.bu_db_status.setStyleSheet("""
            QLabel {
                padding: 12px 16px;
                border-radius: 8px;
                font-size: 12px;
            }
        """)
        bu_layout.addWidget(self.bu_db_status)
        self._refresh_bu_db_status()

        # -- Rebuild DB section ---------------------------------------------
        self.bu_master_widget = FileInputWidget(
            "Master Excel (one sheet per BU, DNS in column A)",
            "Select the master asset inventory Excel file...",
            file_filter="Excel Files (*.xlsx *.xls);;All Files (*)"
        )
        bu_layout.addWidget(self.bu_master_widget)

        self.rebuild_btn = ModernButton("Rebuild BU Database", primary=False)
        self.rebuild_btn.setMinimumHeight(40)
        self.rebuild_btn.clicked.connect(self.start_bu_rebuild)
        bu_layout.addWidget(self.rebuild_btn)

        # -- Separator line -------------------------------------------------
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color: #e5e7eb;")
        bu_layout.addWidget(sep)

        # -- Group section --------------------------------------------------
        self.bu_input_widget = FileInputWidget(
            "Input File (Formatted)",
            "Select a formatted Excel or CSV file..."
        )
        self.bu_output_widget = FileInputWidget(
            "Output File",
            "Choose where to save the grouped file...",
            is_save=True
        )
        self.bu_input_widget.set_output_widget(self.bu_output_widget, suffix="_by_bu.xlsx")

        bu_layout.addWidget(self.bu_input_widget)
        bu_layout.addWidget(self.bu_output_widget)

        self.bu_progress_bar = QProgressBar()
        self.bu_progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #e5e7eb;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #2563eb;
                border-radius: 4px;
            }
        """)
        self.bu_progress_bar.setTextVisible(False)
        self.bu_progress_bar.setValue(0)
        self.bu_progress_bar.setVisible(False)
        bu_layout.addWidget(self.bu_progress_bar)

        self.bu_btn = ModernButton("Group by Business Unit", primary=True)
        self.bu_btn.setMinimumHeight(48)
        self.bu_btn.clicked.connect(self.start_bu_grouping)
        bu_layout.addWidget(self.bu_btn)

        bu_layout.addStretch()
        self.tab_widget.addTab(bu_tab, "🏢 Group by BU")

        # ===== QUALYS PCI TAB =====
        qualys_tab = QWidget()
        qualys_layout = QVBoxLayout(qualys_tab)
        qualys_layout.setContentsMargins(0, 10, 0, 0)
        qualys_layout.setSpacing(16)

        problems = qualys_config_problems()

        endpoint = get_qualys_api_url() or "\u26a0\ufe0f not set"
        api_user = get_qualys_api_user() or "\u26a0\ufe0f not set"
        cred_state = ("\u26a0\ufe0f not configured" if problems
                      else "\U0001f512 stored encrypted")

        conn_label = QLabel(
            f"Endpoint: {endpoint}    •    User: {api_user}    "
            f"•    Password: {cred_state}"
        )
        conn_label.setStyleSheet("QLabel { color: #6b7280; font-size: 12px; }")
        qualys_layout.addWidget(conn_label)

        if problems:
            vault_hint = QLabel(
                "⚠️ Qualys connection not set up yet. Still missing: "
                + ", ".join(problems)
                + ".<br>See the connection settings block at the top of "
                  f"<code>{os.path.basename(__file__)}</code> for details."
            )
            vault_hint.setWordWrap(True)
            vault_hint.setStyleSheet("""
                QLabel {
                    background-color: #fef3c7;
                    color: #92400e;
                    padding: 12px 16px;
                    border-radius: 8px;
                    font-size: 12px;
                    border: 1px solid #fcd34d;
                }
            """)
            qualys_layout.addWidget(vault_hint)

        # Filter controls row
        filters_row = QHBoxLayout()
        filters_row.setSpacing(12)

        title_box = QVBoxLayout()
        title_box.setSpacing(8)
        title_lbl = QLabel("Title contains")
        title_lbl.setStyleSheet("QLabel { color: #374151; font-size: 13px; font-weight: 600; }")
        self.qualys_title_edit = QLineEdit("PCI")
        self.qualys_title_edit.setStyleSheet("""
            QLineEdit {
                background-color: #ffffff;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                padding: 10px 14px;
                font-size: 13px;
                color: #1f2937;
            }
            QLineEdit:focus { border-color: #2563eb; }
        """)
        title_box.addWidget(title_lbl)
        title_box.addWidget(self.qualys_title_edit)
        filters_row.addLayout(title_box, 1)

        state_box = QVBoxLayout()
        state_box.setSpacing(8)
        state_lbl = QLabel("Report state")
        state_lbl.setStyleSheet("QLabel { color: #374151; font-size: 13px; font-weight: 600; }")
        self.qualys_state_combo = QComboBox()
        self.qualys_state_combo.addItem("Finished", "Finished")
        self.qualys_state_combo.addItem("All", "All")
        self.qualys_state_combo.setStyleSheet("""
            QComboBox {
                background-color: #ffffff;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                padding: 10px 14px;
                font-size: 13px;
                color: #1f2937;
            }
            QComboBox:focus { border-color: #2563eb; }
            QComboBox::drop-down { border: none; padding-right: 10px; }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                border: 1px solid #d1d5db;
                selection-background-color: #2563eb;
                selection-color: white;
            }
        """)
        state_box.addWidget(state_lbl)
        state_box.addWidget(self.qualys_state_combo)
        filters_row.addLayout(state_box, 1)

        qualys_layout.addLayout(filters_row)

        self.qualys_month_check = QCheckBox("Only reports launched in the current month")
        self.qualys_month_check.setChecked(True)
        self.qualys_month_check.setStyleSheet("QCheckBox { color: #374151; font-size: 13px; }")
        qualys_layout.addWidget(self.qualys_month_check)

        self.qualys_format_check = QCheckBox("Apply formatting rules after download")
        self.qualys_format_check.setChecked(True)
        self.qualys_format_check.setStyleSheet("QCheckBox { color: #374151; font-size: 13px; }")
        qualys_layout.addWidget(self.qualys_format_check)

        self.qualys_output_widget = FileInputWidget(
            "Download Folder",
            "Choose a folder to save the downloaded reports...",
            is_dir=True,
        )
        qualys_layout.addWidget(self.qualys_output_widget)

        self.qualys_progress_bar = QProgressBar()
        self.qualys_progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #e5e7eb;
                border: none;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #2563eb;
                border-radius: 4px;
            }
        """)
        self.qualys_progress_bar.setTextVisible(False)
        self.qualys_progress_bar.setValue(0)
        self.qualys_progress_bar.setVisible(False)
        qualys_layout.addWidget(self.qualys_progress_bar)

        self.qualys_eula_btn = ModernButton("Accept EULA / Activate Account", primary=False)
        self.qualys_eula_btn.setMinimumHeight(40)
        self.qualys_eula_btn.clicked.connect(self.start_qualys_eula)
        qualys_layout.addWidget(self.qualys_eula_btn)

        self.qualys_btn = ModernButton("Fetch & Format PCI Reports", primary=True)
        self.qualys_btn.setMinimumHeight(48)
        self.qualys_btn.clicked.connect(self.start_qualys_download)
        qualys_layout.addWidget(self.qualys_btn)

        qualys_layout.addStretch()
        self.tab_widget.addTab(qualys_tab, "📥 Qualys PCI")

        main_layout.addWidget(self.tab_widget)
        
        # Log output
        log_label = QLabel("Processing Log")
        log_label.setStyleSheet("color: #374151; font-size: 13px; font-weight: 600;")
        main_layout.addWidget(log_label)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("""
            QTextEdit {
                background-color: #1e293b;
                color: #e2e8f0;
                border: none;
                border-radius: 12px;
                padding: 16px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
            }
        """)
        self.log_output.setMinimumHeight(140)
        main_layout.addWidget(self.log_output)
        
        # Footer
        footer = QLabel("Supports CSV and Excel files • Columns are hidden, not deleted")
        footer.setStyleSheet("color: #9ca3af; font-size: 12px;")
        footer.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(footer)

    # -- BU DB status helpers -----------------------------------------------

    def _refresh_bu_db_status(self):
        meta = BUGrouper.load_db_meta()
        if meta:
            total = meta.get("total_assets", "?")
            bus = meta.get("business_units", [])
            gen = meta.get("generated_at", "unknown")
            # Shorten the ISO timestamp for display
            if "T" in str(gen):
                gen = gen.split("T")[0]
            src = meta.get("source_file", "unknown")
            dupes = meta.get("duplicates_found", 0)

            status_text = (f"✅ Database loaded — {total} assets across {len(bus)} BUs  |  "
                           f"Source: {src}  |  Generated: {gen}")
            if dupes:
                status_text += f"  |  ⚠️ {dupes} duplicate(s)"

            self.bu_db_status.setText(status_text)
            self.bu_db_status.setStyleSheet("""
                QLabel {
                    background-color: #ecfdf5;
                    color: #065f46;
                    padding: 12px 16px;
                    border-radius: 8px;
                    font-size: 12px;
                    border: 1px solid #a7f3d0;
                }
            """)
        else:
            self.bu_db_status.setText(
                "⚠️ No BU database found. Use 'Rebuild Database' above to generate it from your master Excel."
            )
            self.bu_db_status.setStyleSheet("""
                QLabel {
                    background-color: #fef3c7;
                    color: #92400e;
                    padding: 12px 16px;
                    border-radius: 8px;
                    font-size: 12px;
                    border: 1px solid #fcd34d;
                }
            """)

    # -- logging ------------------------------------------------------------

    def log(self, message):
        self.log_output.append(message)
        scrollbar = self.log_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    # -- Format tab ---------------------------------------------------------

    def start_formatting(self):
        input_path = self.input_widget.get_path()
        output_path = self.output_widget.get_path()
        
        if not input_path:
            QMessageBox.warning(self, "Missing Input", "Please select an input file.")
            return
        
        if not os.path.exists(input_path):
            QMessageBox.warning(self, "File Not Found", "The input file does not exist.")
            return
        
        if not output_path:
            QMessageBox.warning(self, "Missing Output", "Please specify an output file path.")
            return
        
        self.log_output.clear()
        self.format_progress_bar.setVisible(True)
        self.format_progress_bar.setValue(0)
        self.format_btn.setEnabled(False)
        self.format_btn.setText("Processing...")
        
        self.log("🚀 Starting file formatting process...")
        
        self.format_worker = FormatterThread(input_path, output_path)
        self.format_worker.progress.connect(self.format_progress_bar.setValue)
        self.format_worker.log_message.connect(self.log)
        self.format_worker.finished_signal.connect(self.formatting_complete)
        self.format_worker.start()
    
    def formatting_complete(self, success, message):
        self.format_btn.setEnabled(True)
        self.format_btn.setText("Format File")
        
        if success:
            self.log(f"\n✨ Formatting complete!")
            self.log(f"📂 Output: {message}")
            
            reply = QMessageBox.question(
                self, "Success",
                f"File formatted successfully!\n\nWould you like to open the output folder?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                folder = os.path.dirname(message)
                os.startfile(folder) if sys.platform == 'win32' else os.system(f'open "{folder}"')
        else:
            self.log(f"\n❌ Formatting failed: {message}")
            QMessageBox.critical(self, "Error", f"Formatting failed:\n{message}")
    
    # -- Compare tab --------------------------------------------------------

    def start_comparison(self):
        file1_path = self.compare_file1_widget.get_path()
        file2_path = self.compare_file2_widget.get_path()
        output_path = self.compare_output_widget.get_path()
        
        if not file1_path:
            QMessageBox.warning(self, "Missing File", "Please select File 1.")
            return
        
        if not os.path.exists(file1_path):
            QMessageBox.warning(self, "File Not Found", "File 1 does not exist.")
            return
        
        if not file2_path:
            QMessageBox.warning(self, "Missing File", "Please select File 2.")
            return
        
        if not os.path.exists(file2_path):
            QMessageBox.warning(self, "File Not Found", "File 2 does not exist.")
            return
        
        if not output_path:
            base = os.path.splitext(file1_path)[0]
            output_path = f"{base}_comparison.xlsx"
            self.compare_output_widget.line_edit.setText(output_path)
        
        self.log_output.clear()
        self.compare_progress_bar.setVisible(True)
        self.compare_progress_bar.setValue(0)
        self.compare_btn.setEnabled(False)
        self.compare_btn.setText("Comparing...")
        
        self.log("🔍 Starting file comparison...")
        
        self.compare_worker = ComparerThread(file1_path, file2_path, output_path)
        self.compare_worker.progress.connect(self.compare_progress_bar.setValue)
        self.compare_worker.log_message.connect(self.log)
        self.compare_worker.finished_signal.connect(self.comparison_complete)
        self.compare_worker.start()
    
    def comparison_complete(self, success, message):
        self.compare_btn.setEnabled(True)
        self.compare_btn.setText("Compare Files")
        
        if success:
            self.log(f"\n✨ Comparison complete!")
            self.log(f"📂 Output: {message}")
            
            reply = QMessageBox.question(
                self, "Success",
                f"Files compared successfully!\n\nWould you like to open the output folder?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                folder = os.path.dirname(message)
                os.startfile(folder) if sys.platform == 'win32' else os.system(f'open "{folder}"')
        else:
            self.log(f"\n❌ Comparison failed: {message}")
            QMessageBox.critical(self, "Error", f"Comparison failed:\n{message}")

    # -- Wiz tab ------------------------------------------------------------

    def start_wiz_parsing(self):
        input_path = self.wiz_input_widget.get_path()
        output_path = self.wiz_output_widget.get_path()

        if not input_path:
            QMessageBox.warning(self, "Missing Input", "Please select a Wiz JSON file.")
            return

        if not os.path.exists(input_path):
            QMessageBox.warning(self, "File Not Found", "The input JSON file does not exist.")
            return

        if not output_path:
            base = os.path.splitext(input_path)[0]
            output_path = f"{base}_cve_findings.csv"
            self.wiz_output_widget.line_edit.setText(output_path)

        self.log_output.clear()
        self.wiz_progress_bar.setVisible(True)
        self.wiz_progress_bar.setValue(0)
        self.wiz_btn.setEnabled(False)
        self.wiz_btn.setText("Parsing...")

        self.log("🛡️ Starting Wiz JSON parsing...")

        self.wiz_worker = WizThread(input_path, output_path)
        self.wiz_worker.progress.connect(self.wiz_progress_bar.setValue)
        self.wiz_worker.log_message.connect(self.log)
        self.wiz_worker.finished_signal.connect(self.wiz_complete)
        self.wiz_worker.start()

    def wiz_complete(self, success, message):
        self.wiz_btn.setEnabled(True)
        self.wiz_btn.setText("Parse Wiz JSON")

        if success:
            self.log(f"\n✨ Wiz parsing complete!")
            self.log(f"📂 Output: {message}")

            reply = QMessageBox.question(
                self, "Success",
                f"Wiz JSON parsed successfully!\n\nWould you like to open the output folder?",
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                folder = os.path.dirname(message)
                os.startfile(folder) if sys.platform == 'win32' else os.system(f'open "{folder}"')
        else:
            self.log(f"\n❌ Wiz parsing failed: {message}")
            QMessageBox.critical(self, "Error", f"Wiz parsing failed:\n{message}")

    # -- Group by BU tab ----------------------------------------------------

    def start_bu_rebuild(self):
        master_path = self.bu_master_widget.get_path()

        if not master_path:
            QMessageBox.warning(self, "Missing Input", "Please select the master Excel file.")
            return

        if not os.path.exists(master_path):
            QMessageBox.warning(self, "File Not Found", "The master Excel file does not exist.")
            return

        self.log_output.clear()
        self.bu_progress_bar.setVisible(True)
        self.bu_progress_bar.setValue(0)
        self.rebuild_btn.setEnabled(False)
        self.rebuild_btn.setText("Building...")

        self.log("🔧 Rebuilding BU database from master Excel...")

        self.bu_build_worker = BUBuilderThread(master_path)
        self.bu_build_worker.progress.connect(self.bu_progress_bar.setValue)
        self.bu_build_worker.log_message.connect(self.log)
        self.bu_build_worker.finished_signal.connect(self.bu_rebuild_complete)
        self.bu_build_worker.start()

    def bu_rebuild_complete(self, success, message):
        self.rebuild_btn.setEnabled(True)
        self.rebuild_btn.setText("Rebuild BU Database")
        self._refresh_bu_db_status()

        if success:
            self.log(f"\n✨ BU database rebuilt successfully!")
            QMessageBox.information(
                self, "Success",
                "BU database rebuilt successfully!\n\n"
                "You can now use 'Group by Business Unit' below."
            )
        else:
            self.log(f"\n❌ Database rebuild failed: {message}")
            QMessageBox.critical(self, "Error", f"Database rebuild failed:\n{message}")

    def start_bu_grouping(self):
        # Re-check DB status in case user just rebuilt it
        self._refresh_bu_db_status()

        if not BUGrouper.db_exists():
            QMessageBox.warning(
                self, "No BU Database",
                "bu_database.json not found.\n\n"
                "Use the 'Rebuild Database' section above to generate it\n"
                "from your master Excel file first."
            )
            return

        input_path = self.bu_input_widget.get_path()
        output_path = self.bu_output_widget.get_path()

        if not input_path:
            QMessageBox.warning(self, "Missing Input", "Please select an input file.")
            return

        if not os.path.exists(input_path):
            QMessageBox.warning(self, "File Not Found", "The input file does not exist.")
            return

        if not output_path:
            base = os.path.splitext(input_path)[0]
            output_path = f"{base}_by_bu.xlsx"
            self.bu_output_widget.line_edit.setText(output_path)

        self.log_output.clear()
        self.bu_progress_bar.setVisible(True)
        self.bu_progress_bar.setValue(0)
        self.bu_btn.setEnabled(False)
        self.bu_btn.setText("Grouping...")

        self.log("🏢 Starting BU grouping...")

        self.bu_worker = BUGrouperThread(input_path, output_path)
        self.bu_worker.progress.connect(self.bu_progress_bar.setValue)
        self.bu_worker.log_message.connect(self.log)
        self.bu_worker.finished_signal.connect(self.bu_grouping_complete)
        self.bu_worker.start()

    def bu_grouping_complete(self, success, message):
        self.bu_btn.setEnabled(True)
        self.bu_btn.setText("Group by Business Unit")

        if success:
            self.log(f"\n✨ BU grouping complete!")
            self.log(f"📂 Output: {message}")

            reply = QMessageBox.question(
                self, "Success",
                f"Assets grouped by Business Unit!\n\nWould you like to open the output folder?",
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                folder = os.path.dirname(message)
                os.startfile(folder) if sys.platform == 'win32' else os.system(f'open "{folder}"')
        else:
            self.log(f"\n❌ BU grouping failed: {message}")
            QMessageBox.critical(self, "Error", f"BU grouping failed:\n{message}")

    # -- Qualys PCI tab -----------------------------------------------------

    def start_qualys_eula(self):
        problems = qualys_config_problems()
        if problems:
            QMessageBox.warning(
                self, "Qualys Not Configured",
                "The Qualys connection is not set up yet.\n\nStill missing:\n  - "
                + "\n  - ".join(problems)
                + "\n\nSee the connection settings block at the top of the script.",
            )
            return

        self.log_output.clear()
        self.qualys_eula_btn.setEnabled(False)
        self.qualys_eula_btn.setText("Activating...")
        self.log("📝 Sending EULA acceptance request to Qualys...")

        self.qualys_eula_worker = QualysEulaThread()
        self.qualys_eula_worker.log_message.connect(self.log)
        self.qualys_eula_worker.finished_signal.connect(self.qualys_eula_complete)
        self.qualys_eula_worker.start()

    def qualys_eula_complete(self, success, message):
        self.qualys_eula_btn.setEnabled(True)
        self.qualys_eula_btn.setText("Accept EULA / Activate Account")

        if success:
            self.log(f"\n✅ {message}")
            QMessageBox.information(self, "Account Activated", message)
        else:
            self.log(f"\n❌ {message}")
            QMessageBox.critical(self, "Error", f"EULA acceptance failed:\n{message}")

    def start_qualys_download(self):
        output_dir = self.qualys_output_widget.get_path()
        title_contains = self.qualys_title_edit.text().strip()
        state = self.qualys_state_combo.currentData()
        current_month_only = self.qualys_month_check.isChecked()
        apply_formatting = self.qualys_format_check.isChecked()

        if not output_dir:
            QMessageBox.warning(self, "Missing Folder", "Please choose a download folder.")
            return

        if not title_contains:
            QMessageBox.warning(self, "Missing Filter", "Please enter a title keyword (e.g. PCI).")
            return

        problems = qualys_config_problems()
        if problems:
            QMessageBox.warning(
                self, "Qualys Not Configured",
                "The Qualys connection is not set up yet.\n\nStill missing:\n  - "
                + "\n  - ".join(problems)
                + "\n\nSee the connection settings block at the top of the script.",
            )
            return

        self.log_output.clear()
        self.qualys_progress_bar.setVisible(True)
        self.qualys_progress_bar.setValue(0)
        self.qualys_btn.setEnabled(False)
        self.qualys_btn.setText("Working...")

        self.log("📥 Starting Qualys report download...")
        self.log(f"🔎 Filter: title contains '{title_contains}', state={state}, "
                 f"current month only={current_month_only}")

        self.qualys_worker = QualysThread(
            output_dir,
            title_contains=title_contains,
            state=state,
            current_month_only=current_month_only,
            apply_formatting=apply_formatting,
        )
        self.qualys_worker.progress.connect(self.qualys_progress_bar.setValue)
        self.qualys_worker.log_message.connect(self.log)
        self.qualys_worker.finished_signal.connect(self.qualys_complete)
        self.qualys_worker.start()

    def qualys_complete(self, success, message):
        self.qualys_btn.setEnabled(True)
        self.qualys_btn.setText("Fetch & Format PCI Reports")

        if success:
            self.log(f"\n✨ Qualys download complete!")
            self.log(f"📂 {message}")

            folder = self.qualys_output_widget.get_path()
            reply = QMessageBox.question(
                self, "Success",
                f"{message}\n\nWould you like to open the download folder?",
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes and folder:
                os.startfile(folder) if sys.platform == 'win32' else os.system(f'open "{folder}"')
        else:
            self.log(f"\n❌ Qualys download failed: {message}")
            QMessageBox.critical(self, "Error", f"Qualys download failed:\n{message}")


def _encrypt_password_cli():
    """Prompt (hidden) for a new password and print its encrypted token."""
    try:
        _vault_secret()
    except VaultNotConfigured as e:
        print(f"\n{e}\n")
        return 1

    pwd = getpass.getpass("New Qualys API password (input hidden): ")
    confirm = getpass.getpass("Confirm password: ")
    if pwd != confirm:
        print("Passwords do not match. Aborted.")
        return 1
    if not pwd:
        print("Empty password. Aborted.")
        return 1

    token = encrypt_secret(pwd)
    print("\nReplace _QUALYS_PWD_TOKEN in the script with:\n")
    print(f'_QUALYS_PWD_TOKEN = "{token}"')
    print(f"\nKeep {_VAULT_SECRET_ENV} set to the same value wherever this token "
          f"needs to be decrypted.")
    return 0


def main():
    if "--encrypt-qualys-password" in sys.argv:
        sys.exit(_encrypt_password_cli())

    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
