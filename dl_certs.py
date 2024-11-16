import sys
import requests
import xml.etree.ElementTree as ET
import os
from urllib.parse import urlparse
import re
import base64
import binascii
from typing import List, Tuple
from pathlib import Path
import chardet
import sqlite3
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.x509.oid import NameOID

def init_database() -> None:
    """
    Initialize the SQLite database with the necessary tables including certificate details.
    Updated to include key format information.
    """
    db_path = 'certificates.db'
    
    # Remove existing database if it exists
    if os.path.exists(db_path):
        try:
            print(f"Removing existing database: {db_path}")
            os.remove(db_path)
        except Exception as e:
            print(f"Error removing existing database: {e}")
            return
    
    print("Creating new database...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create providers table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS providers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        trade_name TEXT,
        original_filename TEXT,
        downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Enhanced certificates table with parsed fields and key format information
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_id INTEGER,
        cert_content BLOB NOT NULL,
        public_key BLOB NOT NULL,
        key_type TEXT NOT NULL,
        key_format TEXT NOT NULL,
        key_info TEXT,
        subject_name TEXT,
        issuer_name TEXT,
        serial_number TEXT,
        not_valid_before TIMESTAMP,
        not_valid_after TIMESTAMP,
        cert_number INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (provider_id) REFERENCES providers (id)
    )
    ''')
    
    # Create indices for common queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_provider_id ON certificates(provider_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_subject_name ON certificates(subject_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_serial_number ON certificates(serial_number)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_key_type ON certificates(key_type)')
    
    conn.commit()
    conn.close()
    print("Database initialization complete!")

def identify_key_type(public_key):
    """Identify the type of public key."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.curve.name
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", None
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", None
    else:
        return "Unknown", None


def get_public_key_info(public_key):
    """
    Get public key information including type, format, and the key bytes.
    Returns tuple of (key_type, key_format, key_info, key_bytes)
    """
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            # Get the SEC1 encoded format with proper point encoding
            # First get the point coordinates
            numbers = public_key.public_numbers()
            # Create uncompressed SEC1 encoding manually: 0x04 || x || y
            # Both x and y should be encoded as fixed-width big-endian integers
            key_size = (public_key.curve.key_size + 7) // 8  # Convert bits to bytes, rounding up
            x_bytes = numbers.x.to_bytes(key_size, byteorder='big')
            y_bytes = numbers.y.to_bytes(key_size, byteorder='big')
            # Prepend 0x04 for uncompressed point format
            key_bytes = b'\x04' + x_bytes + y_bytes
            
            return (
                "EC",
                "SEC1",
                public_key.curve.name,
                key_bytes
            )
        elif isinstance(public_key, rsa.RSAPublicKey):
            return (
                "RSA",
                "SPKI",
                str(public_key.key_size),
                public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key_type = "Ed25519" if isinstance(public_key, ed25519.Ed25519PublicKey) else "Ed448"
            return (
                key_type,
                "RAW",
                None,
                public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
        else:
            raise ValueError(f"Unsupported key type: {type(public_key)}")
    except Exception as e:
        print(f"Error in get_public_key_info: {e}")
        raise

def parse_certificate(cert_content: bytes) -> tuple[dict, dict]:
    """
    Parse a DER formatted certificate and extract relevant fields.
    Returns tuple of (key_info_dict, cert_fields_dict)
    """
    try:
        print("\nParsing certificate:")
        print(f"Certificate size: {len(cert_content)} bytes")
        
        cert = x509.load_der_x509_certificate(cert_content)
        public_key = cert.public_key()
        
        # Get detailed key information
        try:
            key_type, key_format, key_info, key_bytes = get_public_key_info(public_key)
            
            print(f"\nSuccessfully extracted public key:")
            print(f"Type: {key_type}")
            print(f"Format: {key_format}")
            print(f"Info: {key_info}")
            print(f"Key size: {len(key_bytes)} bytes")
            print(f"Key starts with: {key_bytes[:10].hex()}")
            
            if key_type == "EC":
                print(f"EC Point format: {'0x04 (uncompressed)' if key_bytes[0] == 0x04 else 'unknown'}")
                print(f"Coordinate size: {(len(key_bytes)-1)//2} bytes")
            
        except Exception as e:
            print(f"Error extracting key info: {e}")
            raise
        
        key_info_dict = {
            'public_key': key_bytes,
            'key_type': key_type,
            'key_format': key_format,
            'key_info': key_info
        }
        
        cert_fields = {
            'subject_name': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'issuer_name': cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'serial_number': format(cert.serial_number, 'X'),
            'not_valid_before': cert.not_valid_before,
            'not_valid_after': cert.not_valid_after
        }
        
        return key_info_dict, cert_fields
        
    except Exception as e:
        print(f"Error parsing certificate: {e}")
        return None, None

def parse_certs(file_path: str) -> list[bytes]:
    """Parse certificates from a file containing multiple DER certificates."""
    with open(file_path, 'rb') as f:
        content = f.read()
    
    sections = content.split(b'--End')
    certificates = []
    
    for section in sections:
        section = section.replace(b'Content-type', b'Content-Type')
        if b'Content-Type: application/pkix-cert' in section:
            cert_content = section.split(b'Content-Type: application/pkix-cert', 1)[1].strip()
            if cert_content:
                certificates.append(cert_content)
    
    return certificates



def store_certs(provider_name: str, trade_name: str, original_filename: str, certificates: list[bytes]) -> None:
    """Store certificates in SQLite database with detailed key information."""
    conn = sqlite3.connect('certificates.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        INSERT INTO providers (name, trade_name, original_filename)
        VALUES (?, ?, ?)
        ''', (provider_name, trade_name, original_filename))
        
        provider_id = cursor.lastrowid
        
        # Store previously seen public keys for this provider
        seen_public_keys = set()
        
        for i, cert_content in enumerate(certificates, 1):
            print(f"\nProcessing certificate {i} for provider {provider_name}")
            key_info, cert_fields = parse_certificate(cert_content)
            
            if key_info and cert_fields:
                # Check if we've seen this public key before using the actual key bytes
                public_key_hex = key_info['public_key'].hex()  # Convert bytes to hex
                if public_key_hex in seen_public_keys:
                    print("WARNING: Duplicate public key detected!")
                    print(f"Previous certificate from this provider had the same public key")
                else:
                    seen_public_keys.add(public_key_hex)
                
                cursor.execute('''
                INSERT INTO certificates (
                    provider_id, cert_content, public_key,
                    key_type, key_format, key_info,
                    subject_name, issuer_name, serial_number, 
                    not_valid_before, not_valid_after, cert_number
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    provider_id, cert_content, key_info['public_key'],
                    key_info['key_type'], key_info['key_format'], key_info['key_info'],
                    cert_fields['subject_name'], cert_fields['issuer_name'],
                    cert_fields['serial_number'], cert_fields['not_valid_before'],
                    cert_fields['not_valid_after'], i
                ))
        
        conn.commit()
        print(f"\nStored {len(certificates)} certificates for provider: {provider_name}")
        print(f"Unique public keys found: {len(seen_public_keys)}")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
    except Exception as e:
        print(f"Error processing certificates: {e}")
        conn.rollback()
    
    finally:
        conn.close()

def get_provider_name(provider):
    """Extract provider name and trade name from TSPInformation"""
    try:
        name = provider.find('.//tsl:TSPName/tsl:Name[@xml:lang="en"]', namespaces).text
        trade_name = provider.find('.//tsl:TSPTradeName/tsl:Name[@xml:lang="en"]', namespaces).text
        return name, trade_name
    except:
        return "unknown_provider", "unknown_trade_name"

def download_2ddoc_files(xml_url):
    download_dir = 'temp_cert_files'
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0'
    }
    
    try:
        response = requests.get(xml_url, headers=headers, verify=False)
        response.raise_for_status()
        
        root = ET.fromstring(response.text)
        providers = root.findall('.//tsl:TrustServiceProvider', namespaces)
        
        downloaded_files = []
        for provider in providers:
            name, trade_name = get_provider_name(provider)
            
            uri_element = provider.find('.//tsl:TSPInformation/tsl:TSPInformationURI/tsl:URI[@xml:lang="fr"]', namespaces)
            
            if uri_element is not None and uri_element.text:
                url = uri_element.text
                try:
                    print(f"Downloading: {url}")
                    der_response = requests.get(url, headers=headers, verify=False)
                    der_response.raise_for_status()
                    
                    original_filename = os.path.basename(urlparse(url).path)
                    temp_filepath = os.path.join(download_dir, f"{name}_{original_filename}")
                    
                    with open(temp_filepath, 'wb') as f:
                        f.write(der_response.content)
                    
                    # Parse and store certificates
                    certs = parse_certs(temp_filepath)
                    if certs:
                        store_certs(name, trade_name, original_filename, certs)
                    
                    # Clean up temporary file
                    os.remove(temp_filepath)
                    print(f"Successfully processed certificates for: {name}")
                    
                except requests.RequestException as e:
                    print(f"Failed to download {url}: {str(e)}")
                    continue
        
    except requests.RequestException as e:
        print(f"Failed to fetch XML from {xml_url}: {str(e)}")
    except ET.ParseError as e:
        print(f"Failed to parse XML: {str(e)}")

# Define the XML namespaces
namespaces = {
    'tsl': 'http://uri.etsi.org/02231/v2#',
    'xml': 'http://www.w3.org/XML/1998/namespace'
}


if __name__ == "__main__":
    if sys.prefix == sys.base_prefix:
        print("please run the script in the venv")
        sys.exit() 
    xml_url = "https://ants.gouv.fr/files/25362bbf-a54e-4ed9-b98a-71e2382b54e0/tsl_signed.xml"
    
    print("Starting download of .2ddoc files...")
    init_database()
    
    print("Starting download and processing of certificate files...")
    download_2ddoc_files(xml_url)
    
    print("Processing complete!")
