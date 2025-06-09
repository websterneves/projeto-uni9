from flask import Flask, request, redirect, url_for, jsonify, session
from flask_cors import CORS
from flask_mysqldb import MySQL 
import hashlib 
import requests 
import uuid 
import json
import base64
import email 
from email import policy 


from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow 
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


import config
import db_operations 
import phishing_analyzer

app = Flask(__name__)

CORS(app) 

app.secret_key = 'super_secret_key_para_sessao_flask_nao_usar_em_producao_mude_isso'

app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_PORT'] = config.MYSQL_PORT
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DATABASE

mysql = MySQL(app)


@app.route('/cadastro', methods=['POST'])
def cadastro():
    dados = request.get_json()

    user = dados.get('user')
    email_user = dados.get('email') 
    senha = dados.get('senha')
    confirmacao = dados.get('confirmacao')

    if not user or not email_user or not senha or not confirmacao:
        return jsonify({'erro': 'Todos os campos são obrigatórios.'}), 400

    if senha != confirmacao:
        return jsonify({'erro': 'As senhas não coincidem.'}), 400

    try:
        cursor = mysql.connection.cursor()

        cursor.execute("SELECT * FROM user WHERE user = %s OR email = %s", (user, email_user))
        existente = cursor.fetchone()
        if existente:
            return jsonify({'erro': 'Usuário ou e-mail já cadastrado.'}), 400

        senha_hash = hashlib.md5(f"projeto_{senha}".encode()).hexdigest()

        cursor.execute(
            "INSERT INTO user (user, email, senha) VALUES (%s, %s, %s)",
            (user, email_user, senha_hash)
        )
        mysql.connection.commit()
        cursor.close()

        return jsonify({'mensagem': 'Usuário cadastrado com sucesso!'}), 201

    except Exception as e:
        print(f"Erro no cadastro: {e}")
        return jsonify({'erro': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    dados = request.get_json()

    user = dados.get('user')
    senha = dados.get('senha')

    if not user or not senha:
        return jsonify({'erro': 'Usuário e senha são obrigatórios.'}), 400

    try:
        cursor = mysql.connection.cursor()

        senha_hash = hashlib.md5(f"projeto_{senha}".encode()).hexdigest()

        cursor.execute("SELECT id, user, email FROM user WHERE user = %s AND senha = %s", (user, senha_hash))
        resultado = cursor.fetchone()
        cursor.close()

        if resultado:

            return jsonify({'mensagem': 'Login bem-sucedido!', 'user_id': resultado[1]}), 200 
        else:
            return jsonify({'erro': 'Usuário ou senha incorretos.'}), 401

    except Exception as e:
        print(f"Erro no login: {e}")
        return jsonify({'erro': str(e)}), 500



@app.route('/api/auth/google/callback', methods=['GET'])
def google_auth_callback():
    """
    Recebe o redirecionamento do Google após o usuário autorizar.
    Troca o código de autorização por tokens e os armazena no DB.
    """
    code = request.args.get('code')
    state = request.args.get('state') 
    error_param = request.args.get('error')


    user_id_for_callback = state 

    if not user_id_for_callback: 
        print("Erro: ID do usuário (state) não fornecido no callback do Google.")
        return f"<html><body><h1>Erro de Autenticação</h1><p>Erro: ID do usuário ausente no retorno do Google. Por favor, reinicie o processo de conexão do Gmail no aplicativo.</p><p>Você pode fechar esta janela.</p></body></html>", 400

    if error_param:
        print(f"Autorização negada pelo usuário {user_id_for_callback}: {error_param}")
        return f"<html><body><h1>Erro de Autenticação</h1><p>Autorização do Gmail negada para o usuário {user_id_for_callback}: {error_param}</p><p>Você pode fechar esta janela e voltar ao aplicativo.</p></body></html>", 400

    if not code:
        print(f"Código de autorização não fornecido pelo Google para {user_id_for_callback}.")
        return "<html><body><h1>Erro de Autenticação</h1><p>Código de autorização ausente. Por favor, tente novamente.</p><p>Você pode fechar esta janela e voltar ao aplicativo.</p></body></html>", 400



    try:
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": config.TOKEN_URI,
                    "redirect_uris": [config.REDIRECT_URI], 
                }
            },
            scopes=config.SCOPES,
            redirect_uri=config.REDIRECT_URI
        )

        flow.fetch_token(code=code)
        credentials = flow.credentials

        db_operations.save_tokens_for_user(
            user_id_for_callback, 
            credentials.refresh_token, 
            credentials.token, 
            credentials.scopes 
        )


        return f"<html><body><h1>Autenticação Concluída</h1><p>Gmail conectado com sucesso para o usuário <b>{user_id_for_callback}</b>!</p><p>Você pode fechar esta janela e voltar ao aplicativo.</p></body></html>"

    except Exception as e:
        print(f"Erro ao trocar código por tokens no callback para {user_id_for_callback}: {e}")
        return f"<html><body><h1>Erro de Autenticação</h1><p>Erro ao processar sua autenticação Gmail: {str(e)}</p><p>Você pode fechar esta janela e voltar ao aplicativo.</p></body></html>", 500

@app.route('/api/gmail/connect-or-check', methods=['GET'])
def connect_or_check_gmail_auth():
    """
    Endpoint consolidado para verificar o status de autenticação do Gmail ou iniciar o fluxo OAuth.
    Se o usuário não estiver autenticado ou o token for inválido, retorna a URL de autorização.
    """
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"authenticated": False, "message": "ID do usuário não fornecido."}), 400

    refresh_token, last_access_token, scopes = db_operations.get_tokens_for_user(user_id)
    
    # Verifica se já temos um token válido e com os escopos corretos
    if refresh_token:
        try:
            creds = Credentials(
                token=last_access_token, 
                refresh_token=refresh_token,
                token_uri=config.TOKEN_URI,
                client_id=config.CLIENT_ID,
                client_secret=config.CLIENT_SECRET,
                scopes=scopes 
            )
            # Tenta renovar o token se expirado
            if not creds.valid and creds.refresh_token:
                creds.refresh(Request())
                db_operations.save_tokens_for_user(user_id, creds.refresh_token, creds.token, creds.scopes)
                print(f"Tokens Gmail renovados para {user_id}.")
            
            # Se o token for válido E tiver o escopo de leitura, o usuário está autenticado.
            if creds.valid and 'https://www.googleapis.com/auth/gmail.readonly' in creds.scopes:
                return jsonify({"authenticated": True, "message": "Gmail conectado e válido.", "user_id": user_id}), 200
            else:
                # Token não é válido ou escopo insuficiente, precisa reautenticar.
                print(f"Token Gmail inválido ou escopos insuficientes para {user_id}. Iniciando novo fluxo de autenticação.")
        except Exception as e:
            print(f"Erro ao validar/renovar token para {user_id}: {e}. Forçando reautenticação.")

    
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": config.CLIENT_ID,
                "client_secret": config.CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": config.TOKEN_URI,
                "redirect_uris": [config.REDIRECT_URI], 
            }
        },
        scopes=config.SCOPES,
        redirect_uri=config.REDIRECT_URI
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline', 
        include_granted_scopes='true',
        prompt='consent', 
        state=user_id 
    )

    return jsonify({
        "authenticated": False,
        "message": "Inicie a autenticação do Google.",
        "authorization_url": authorization_url
    }), 200


@app.route('/api/gmail/analyze-messages', methods=['GET'])
def analyze_gmail_messages():
    """
    Endpoint para buscar e analisar as últimas mensagens de e-mail de um usuário.
    Retorna apenas os e-mails suspeitos.
    """
    user_id = request.args.get('user_id') 
    if not user_id:
        return jsonify({"message": "ID do usuário não fornecido para análise de e-mails."}), 400

    refresh_token, last_access_token, stored_scopes = db_operations.get_tokens_for_user(user_id)

    if not refresh_token:
        return jsonify({"message": "Usuário não autenticado no Gmail ou refresh token não encontrado. Por favor, conecte o Gmail."}), 401
    
    if 'https://www.googleapis.com/auth/gmail.readonly' not in stored_scopes:
        return jsonify({"message": "O token do usuário não possui o escopo necessário para acessar o conteúdo completo (RAW) dos e-mails. Por favor, reautentique o Gmail aceitando todas as permissões."}), 403

    try:

        credentials = Credentials(
            token=last_access_token, 
            refresh_token=refresh_token,
            token_uri=config.TOKEN_URI,
            client_id=config.CLIENT_ID,
            client_secret=config.CLIENT_SECRET,
            scopes=stored_scopes 
        )

        if not credentials.valid:
            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                db_operations.save_tokens_for_user(user_id, credentials.refresh_token, credentials.token, credentials.scopes)
                print(f"Tokens Gmail renovados para {user_id} antes da análise.")
            else:
                return jsonify({"message": "Credenciais do Gmail inválidas ou sem refresh token para renovação. Por favor, reautentique."}), 401

        service = build('gmail', 'v1', credentials=credentials)

        results = service.users().messages().list(userId='me', maxResults=config.MAX_EMAILS_TO_FETCH).execute() 
        messages = results.get('messages', [])

        suspicious_emails_data = []
        if not messages:
            print(f"Nenhuma mensagem encontrada para o usuário {user_id}.")
        else:
            for message_id_obj in messages:
                try:
                    msg_raw = service.users().messages().get(userId='me', id=message_id_obj['id'], format='raw').execute() 
                    raw_email_content_bytes = base64.urlsafe_b64decode(msg_raw['raw'])
                    raw_email_content_str = raw_email_content_bytes.decode('utf-8', errors='ignore')

                    parsed_email_message = email.message_from_string(raw_email_content_str, policy=policy.default)
                    msg_from = parsed_email_message['From'] if 'From' in parsed_email_message else 'N/A'
                    msg_subject = parsed_email_message['Subject'] if 'Subject' in parsed_email_message else 'N/A'
                    
                    analysis_results = phishing_analyzer.analyze_email_for_phishing(raw_email_content_str)
                    
                    if analysis_results['suspicious']:
                        suspicious_emails_data.append({
                            "id": message_id_obj['id'],
                            "from": msg_from,
                            "subject": msg_subject,
                            "risk_score": analysis_results['risk_score'],
                            "suspicious_level": analysis_results['suspicious_level'],
                            "indicators": analysis_results['indicators']
                        })
                except HttpError as inner_error:
                    print(f"Erro ao buscar mensagem {message_id_obj['id']} para {user_id}: {inner_error}")

                except Exception as inner_e:
                    print(f"Erro interno ao processar mensagem {message_id_obj['id']}: {inner_e}")
        
        return jsonify({"messages": suspicious_emails_data}), 200

    except HttpError as error:
        print(f"Ocorreu um erro ao acessar a Gmail API no backend: {error}")
        return jsonify({"message": f"Erro ao acessar o Gmail: {str(error)}"}), 500
    except Exception as e:
        print(f"Erro inesperado no backend ao analisar mensagens: {e}")
        return jsonify({"message": f"Erro interno do servidor: {str(e)}"}), 500

#@app.route('/api/phishing/add-keyword', methods=['POST'])
#def add_keyword():
#    data = request.get_json()
#    keyword = data.get('keyword')
#    if not keyword:
#        return jsonify({"message": "Palavra-chave não fornecida."}), 400
#    
#    phishing_analyzer.add_suspicious_keyword(keyword)
#    return jsonify({"message": f"Palavra-chave '{keyword}' adicionada com sucesso."}), 200
#
#@app.route('/api/phishing/add-shortener', methods=['POST'])
#def add_shortener():
#    data = request.get_json()
#    domain = data.get('domain')
#    if not domain:
#        return jsonify({"message": "Domínio não fornecido."}), 400
#    
#    phishing_analyzer.add_url_shortener(domain)
#    return jsonify({"message": f"Encurtador '{domain}' adicionado com sucesso."}), 200
#
#@app.route('/api/phishing/add-attachment-type', methods=['POST'])
#def add_attachment_type():
#    data = request.get_json()
#    mime_type = data.get('mime_type')
#    if not mime_type:
#        return jsonify({"message": "Tipo MIME não fornecido."}), 400
#    
#    phishing_analyzer.add_high_risk_attachment_type(mime_type)
#    return jsonify({"message": f"Tipo de anexo '{mime_type}' adicionado com sucesso."}), 200
#
#@app.route('/api/phishing/add-legit-org-domain', methods=['POST'])
#def add_legit_org_domain():
#    data = request.get_json()
#    org_name = data.get('org_name')
#    domain = data.get('domain')
#    if not org_name or not domain:
#        return jsonify({"message": "Nome da organização ou domínio não fornecidos."}), 400
#    
#    phishing_analyzer.add_legit_domain_for_organization(org_name, domain)
#    return jsonify({"message": f"Domínio '{domain}' adicionado para '{org_name}' com sucesso."}), 200
#
#@app.route('/api/phishing/add-legit-host', methods=['POST'])
#def add_legit_host():
#    data = request.get_json()
#    host = data.get('host')
#    if not host:
#        return jsonify({"message": "Host não fornecido."}), 400
#    
#    if hasattr(phishing_analyzer, 'add_known_legit_host'):
#        phishing_analyzer.add_known_legit_host(host)
#        return jsonify({"message": f"Host legítimo '{host}' adicionado com sucesso."}), 200
#    else:
#        return jsonify({"message": "Funcionalidade 'add_known_legit_host' não implementada no analisador de phishing."}), 501
#
#
#@app.route('/api/phishing/config', methods=['GET'])
#def get_phishing_config():
#    """
#    Retorna a configuração atual do analisador de phishing para o frontend.
#    """
#    try:
#
#        phishing_analyzer._load_config() 
#        current_config = {
#            "suspicious_keywords": phishing_analyzer.SUSPICIOUS_KEYWORDS,
#            "url_shorteners": phishing_analyzer.URL_SHORTENERS,
#            "risk_scores": phishing_analyzer.RISK_SCORES,
#            "high_risk_attachment_types": phishing_analyzer.HIGH_RISK_ATTACHMENT_TYPES,
#            "known_legit_organizations_and_domains": phishing_analyzer.KNOWN_LEGIT_ORGANIZATIONS_AND_DOMAINS,
#            "known_legit_hosts": phishing_analyzer.KNOWN_LEGIT_HOSTS,
#            "suspicious_threshold": phishing_analyzer._get_default_config()["suspicious_threshold"],
#            "medium_threshold": phishing_analyzer._get_default_config()["medium_threshold"]
#        }
#        return jsonify(current_config), 200
#    except Exception as e:
#        print(f"Erro ao obter configurações de phishing: {e}")
#        return jsonify({"message": f"Erro ao carregar configurações: {str(e)}"}), 500


if __name__ == '__main__':

    db_operations.init_db()

    if not hasattr(config, 'MAX_EMAILS_TO_FETCH'):
        config.MAX_EMAILS_TO_FETCH = 10 

    app.run(debug=True, port=5000)
