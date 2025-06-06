import os
import json
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import email 
from email import policy 

import config 
import db_operations 
import phishing_analyzer 


CLIENT_SECRETS_FILE = 'client_secrets.json'


SCOPES = config.SCOPES 

def authenticate_user(user_id):
    """
    Inicia o fluxo OAuth 2.0 para um usuário e armazena o refresh_token no DB.
    Se o usuário já tiver um refresh_token, ele será recarregado e renovado se necessário.
    """
    credentials = None

    refresh_token_stored, last_access_token_stored, scopes_stored = db_operations.get_tokens_for_user(user_id)


    requires_reauth = False
    if refresh_token_stored:
        # Verifica se todos os escopos *desejados* estão presentes nos escopos *armazenados*
        if not all(s in scopes_stored for s in SCOPES):
            print(f"Os escopos armazenados para {user_id} ({scopes_stored}) não incluem todos os escopos necessários ({SCOPES}). Forçando nova autenticação.")
            requires_reauth = True
        else:
            # Se os escopos estiverem corretos, tenta carregar as credenciais
            print(f"Tentando carregar credenciais existentes para o usuário {user_id} do DB...")
            try:
                with open(CLIENT_SECRETS_FILE, 'r') as f:
                    client_config_data = json.load(f)['installed']
                
                credentials = Credentials(
                    token=last_access_token_stored,
                    refresh_token=refresh_token_stored,
                    token_uri=client_config_data.get('token_uri', "https://oauth2.googleapis.com/token"),
                    client_id=client_config_data['client_id'],
                    client_secret=client_config_data['client_secret'],
                    scopes=scopes_stored # Importante: usa os escopos *armazenados* ao carregar, não os globais SCOPES
                )
                
                # Se o token não for válido (expirou ou foi revogado), tenta renovar ou força reautenticação
                if not credentials.valid:
                    if credentials.expired and credentials.refresh_token:
                        print("Access token expirado, tentando renovar...")
                        credentials.refresh(Request())
                        # Salva o novo access_token e o refresh_token (se mudou) de volta no DB
                        db_operations.save_tokens_for_user(user_id, credentials.refresh_token, credentials.token, credentials.scopes)
                        print("Access token renovado com sucesso e salvo no DB.")
                    else:
                        print("Credenciais existentes inválidas ou sem refresh token para renovação. Forçando nova autenticação.")
                        requires_reauth = True # Força nova autenticação
                elif credentials.valid:
                    print("Credenciais existentes são válidas e carregadas.")
            except FileNotFoundError:
                print(f"ERRO: O arquivo '{CLIENT_SECRETS_FILE}' não foi encontrado. Certifique-se de que está na mesma pasta.")
                return None
            except Exception as e:
                print(f"Erro ao carregar ou renovar credenciais para {user_id} do DB: {e}. Forçando nova autenticação.")
                credentials = None
                requires_reauth = True 
    else:
        requires_reauth = True # Sem token armazenado, precisa de nova autenticação
    
    # Se precisar de reautenticação (ou autenticação inicial)
    if requires_reauth or not credentials or not credentials.valid:
        print(f"Iniciando novo fluxo de autenticação OAuth para o usuário {user_id} no navegador...")

        flow = InstalledAppFlow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, SCOPES # Usa os SCOPES GLOBAIS (todos os necessários) para a autenticação
        )
        credentials = flow.run_local_server(port=0) 


        db_operations.save_tokens_for_user(user_id, credentials.refresh_token, credentials.token, credentials.scopes)
        print(f"Autenticação bem-sucedida para o usuário {user_id}. Tokens armazenados no DB.")

    return credentials

def get_gmail_service(credentials):
    """
    Constrói e retorna o serviço da Gmail API usando as credenciais fornecidas.
    """
    try:
        service = build('gmail', 'v1', credentials=credentials)
        print("Serviço Gmail API construído com sucesso.")
        return service
    except HttpError as error:
        print(f"Ocorreu um erro ao construir o serviço da Gmail API: {error}")
        return None

def fetch_and_analyze_messages(service, user_id, max_results=10):
    """
    Busca e analisa as últimas mensagens do Gmail para sinais de phishing.
    Apenas exibe os e-mails classificados como suspeitos.
    """
    try:
        # Lista as mensagens do usuário
        results = service.users().messages().list(userId='me', maxResults=max_results).execute()
        messages = results.get('messages', [])

        if not messages:
            print(f"Nenhuma mensagem encontrada para o usuário {user_id}.")
            return

        print(f"\nAnalisando as últimas {len(messages)} mensagens para o usuário {user_id} (exibindo apenas as suspeitas):")
        suspicious_count = 0
        for i, message_id_obj in enumerate(messages):

            msg_raw = service.users().messages().get(userId='me', id=message_id_obj['id'], format='raw').execute() 

            raw_email_content_bytes = base64.urlsafe_b64decode(msg_raw['raw'])
            raw_email_content_str = raw_email_content_bytes.decode('utf-8', errors='ignore')


            parsed_email_message = email.message_from_string(raw_email_content_str, policy=policy.default)


            msg_from = parsed_email_message['From'] if 'From' in parsed_email_message else 'N/A'
            msg_subject = parsed_email_message['Subject'] if 'Subject' in parsed_email_message else 'N/A'

            analysis_results = phishing_analyzer.analyze_email_for_phishing(raw_email_content_str)

            if analysis_results['suspicious']:
                suspicious_count += 1
                print(f"\n--- Mensagem Suspeita {suspicious_count} (ID: {message_id_obj['id']}) ---")
                print(f"  De: {msg_from}")
                print(f"  Assunto: {msg_subject}")
                print(f"  Pontuação de Risco: {analysis_results['risk_score']} ({analysis_results['suspicious_level']})")
                print(f"  Suspeito: SIM")
                if analysis_results['indicators']:
                    print("  Indicadores Detectados:")
                    for indicator in analysis_results['indicators']:
                        print(f"    - {indicator}")
                print("-" * 50)
        
        if suspicious_count == 0:
            print("Nenhum e-mail suspeito encontrado entre as mensagens analisadas.")

    except HttpError as error:
        print(f"Ocorreu um erro ao buscar/analisar mensagens do Gmail: {error}")
        # Se o erro for 403 (Forbidden) e indicar problema de escopo, sugere reautenticação
        if error.resp.status == 403 and ("Metadata scope doesn't allow format RAW" in str(error) or "Insufficient Permission" in str(error) or "Request had insufficient authentication scopes." in str(error)):
            print("\nATENÇÃO: O token do usuário não possui o escopo necessário para 'RAW' content.")
            print("Por favor, delete o token deste usuário no banco de dados e reautentique-o,")
            print("garantindo que você aceite todas as permissões solicitadas na tela do Google.")
            print("Verifique também se 'https://www.googleapis.com/auth/gmail.readonly' está no seu config.py e no Google Cloud Console.")
        else:
            print(f"Detalhes do erro HTTP: {error.resp.status} - {error.resp.reason}")
            print(f"Mensagem da API: {error.content.decode('utf-8')}")
    except Exception as e:
        print(f"Erro inesperado durante a busca e análise de mensagens: {e}")

if __name__ == '__main__':
    print("--- Sistema de Análise de Phishing (Desktop) ---")
    
    db_operations.init_db()


    current_user_id = input("Digite um ID de usuário (ex: 'joao123' ou 'maria456'): ")

    try:

        credentials = authenticate_user(current_user_id)

        if credentials:

            service = get_gmail_service(credentials)

            if service:

                fetch_and_analyze_messages(service, current_user_id)
        else:
            print("Não foi possível autenticar o usuário. Verifique as configurações e tente novamente.")

    except Exception as e:
        print(f"\nOcorreu um erro fatal inesperado: {e}")

