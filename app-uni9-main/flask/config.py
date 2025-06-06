import os
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURAÇÕES NECESSÁRIAS PARA O GOOGLE OAUTH ---
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI')

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.metadata'
]

TOKEN_URI = 'https://oauth2.googleapis.com/token'

# --- CONFIGURAÇÕES DO BANCO DE DADOS MYSQL ---
MYSQL_HOST = os.getenv('MYSQL_HOST')
MYSQL_USER = os.getenv('MYSQL_USER')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
MYSQL_DATABASE = os.getenv('MYSQL_DATABASE')
MYSQL_PORT = int(os.getenv('MYSQL_PORT'))

# --- CHAVE DE CRIPTOGRAFIA ---
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY').encode()

# --- CONFIGURAÇÕES DO BACKEND FLASK ---
FLASK_BACKEND_URL = os.getenv('FLASK_BACKEND_URL')

# --- OUTRAS CONFIGURAÇÕES ---
MAX_EMAILS_TO_FETCH = int(os.getenv('MAX_EMAILS_TO_FETCH'))
