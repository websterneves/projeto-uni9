import mysql.connector
from mysql.connector import Error
from cryptography.fernet import Fernet
import json

import config # Importa as configurações do nosso arquivo config.py

# Inicializa o Fernet com a chave de criptografia do config.py
try:
    cipher_suite = Fernet(config.ENCRYPTION_KEY)
except ValueError as e:
    print(f"ERRO DE CONFIGURAÇÃO: Chave de criptografia inválida em config.py: {e}")
    print("Por favor, gere uma nova chave usando 'python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key())\"' e atualize config.py.")
    exit(1) # Sai do programa se a chave for inválida

def _encrypt_data(data):
    """Criptografa os dados antes de salvar no banco."""
    try:
        # data deve ser bytes, então codificamos a string
        return cipher_suite.encrypt(data.encode('utf-8'))
    except Exception as e:
        print(f"Erro ao criptografar dados: {e}")
        raise # Re-lança a exceção para que o chamador saiba que falhou

def _decrypt_data(encrypted_data):
    """Descriptografa os dados ao recuperar do banco."""
    try:
        # Retorna string decodificada
        return cipher_suite.decrypt(encrypted_data).decode('utf-8')
    except Exception as e:
        print(f"Erro ao descriptografar dados: {e}. A chave pode estar errada ou os dados corrompidos.")
        raise # Re-lança a exceção

def get_db_connection():
    """Tenta estabelecer uma conexão com o banco de dados MySQL."""
    print("Tentando conectar ao MySQL...")
    try:
        conn = mysql.connector.connect(
            host=config.MYSQL_HOST,
            database=config.MYSQL_DATABASE,
            user=config.MYSQL_USER,
            password=config.MYSQL_PASSWORD,
            port=config.MYSQL_PORT, # <<< ESTA LINHA É CRUCIAL PARA PASSAR A PORTA CORRETA
            # Se a conexão falhar novamente com um erro relacionado a SSL,
            # você pode precisar adicionar os parâmetros SSL aqui, como:
            # ssl_ca='caminho/para/seu/ca.pem',
            # ssl_verify_cert=True,
            # ssl_disabled=False, # Geralmente True para habilitar SSL com certificados
        )
        if conn.is_connected():
            print(f"Conexão bem-sucedida ao banco de dados MySQL: {config.MYSQL_DATABASE} na porta {config.MYSQL_PORT}")
            return conn
    except Error as e:
        print(f"Erro ao conectar ao MySQL: {e}")
        # Detalhes adicionais podem ser úteis:
        if "10060" in str(e) or "Can't connect" in str(e):
            print("Verifique seu firewall (IP permitido na Aiven) e a porta configurada.")
        return None

def init_db():
    """
    Cria a tabela gmail_user_tokens se ela não existir.
    Deve ser chamada uma vez ao iniciar a aplicação.
    """
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            create_table_query = """
            CREATE TABLE IF NOT EXISTS gmail_user_tokens (
                user_id VARCHAR(255) PRIMARY KEY,
                refresh_token TEXT NOT NULL,
                access_token TEXT,
                scopes TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
            """
            cursor.execute(create_table_query)
            conn.commit() # <<< Adicionado para garantir a persistência da criação da tabela
            print("Tabela 'gmail_user_tokens' verificada/criada com sucesso.")
        except Error as e:
            print(f"Erro ao criar/verificar tabela: {e}")
            conn.rollback() # Em caso de erro na criação da tabela
        finally:
            cursor.close()
            conn.close()

def save_tokens_for_user(user_id, refresh_token, access_token, scopes):
    """
    Salva ou atualiza os tokens do Google para um usuário no banco de dados.
    O refresh_token é criptografado antes de ser salvo.
    """
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            # Criptografa o refresh_token
            encrypted_refresh_token = _encrypt_data(refresh_token)
            # Converte a lista de escopos para string JSON para armazenamento
            scopes_str = json.dumps(scopes)

            # Usamos INSERT ... ON DUPLICATE KEY UPDATE para inserir ou atualizar
            query = """
            INSERT INTO gmail_user_tokens (user_id, refresh_token, access_token, scopes)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                refresh_token = VALUES(refresh_token),
                access_token = VALUES(access_token),
                scopes = VALUES(scopes),
                updated_at = CURRENT_TIMESTAMP;
            """
            # user_token foi um erro. Corrigido para user_id
            cursor.execute(query, (user_id, encrypted_refresh_token, access_token, scopes_str)) 
            conn.commit()
            print(f"Tokens salvos/atualizados no DB para o usuário: {user_id}")
            return True
        except Error as e:
            print(f"Erro ao salvar tokens no DB para o usuário {user_id}: {e}")
            conn.rollback() # Em caso de erro ao salvar tokens
            return False
        except Exception as e:
            print(f"Erro inesperado durante a criptografia ou JSON.dumps para {user_id}: {e}")
            if conn: conn.rollback()
            return False
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
    return False

def get_tokens_for_user(user_id):
    """
    Recupera os tokens e escopos de um usuário do banco de dados.
    O refresh_token é descriptografado após a recuperação.
    Retorna (refresh_token, access_token, scopes) ou (None, None, None).
    """
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(buffered=True) # buffered=True é útil para SELECTs
            query = "SELECT refresh_token, access_token, scopes FROM gmail_user_tokens WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()

            if result:
                encrypted_refresh_token, access_token, scopes_str = result
                # Descriptografa o refresh_token
                decrypted_refresh_token = _decrypt_data(encrypted_refresh_token)
                # Converte a string JSON de escopos de volta para lista
                scopes = json.loads(scopes_str)
                print(f"Tokens recuperados do DB para o usuário: {user_id}")
                return decrypted_refresh_token, access_token, scopes
            else:
                print(f"Nenhum token encontrado para o usuário: {user_id}")
                return None, None, None
        except Error as e:
            print(f"Erro ao recuperar tokens do DB para o usuário {user_id}: {e}")
            return None, None, None
        except Exception as e: # Erro na descriptografia ou JSON parsing
            print(f"Erro de processamento de tokens recuperados para {user_id}: {e}. O token pode estar corrompido ou a chave errada.")
            # Opcional: Aqui você pode decidir se quer deletar o registro corrompido ou apenas retornar None
            return None, None, None
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
    return None, None, None

def delete_tokens_for_user(user_id):
    """Deleta os tokens de um usuário do banco de dados."""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = "DELETE FROM gmail_user_tokens WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            conn.commit()
            print(f"Tokens deletados do DB para o usuário: {user_id}")
            return True
        except Error as e:
            print(f"Erro ao deletar tokens do DB para o usuário {user_id}: {e}")
            conn.rollback()
            return False
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
    return False

