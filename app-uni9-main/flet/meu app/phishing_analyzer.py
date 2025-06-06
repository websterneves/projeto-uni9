import email
from email import policy
import re
import json
import base64
from urllib.parse import urlparse, urljoin

# Lista de palavras-chave suspeitas que geralmente aparecem em e-mails de phishing
SUSPICIOUS_KEYWORDS = [
    "urgente", "ação necessária", "conta bloqueada", "verifique sua conta",
    "senha expirada", "atualize suas informações", "notificação de segurança",
    "tentativa de login", "suspensão de serviço", "fatura pendente",
    "reembolso", "prêmio", "ganhou", "clique aqui", "imediatamente",
    "restrição", "verificação", "cartão", "dados pessoais","ação imediata necessária", "urgente", "sua conta será suspensa",
    "evite o bloqueio da conta", "prazo final", "último aviso",
    "verificação obrigatória", "responda imediatamente", "atualização urgente",
    "detectamos atividade suspeita", "sua conta será desativada",
    "falha na transação", "pagamento recusado", "problema com seu cartão",
    "atualize os dados de faturamento", "fatura disponível",
    "erro na cobrança", "clique para revisar seu pagamento",
    "transação pendente", "comprovante em anexo",
    "você ganhou", "parabéns", "resgate seu brinde",
    "cupom exclusivo", "clique para receber", "oferta limitada",
    "brinde garantido", "prêmio disponível",
    "nova tentativa de login detectada", "alerta de segurança",
    "mudança de senha necessária", "acesso não autorizado identificado",
    "clique aqui para proteger sua conta", "confirme seus dados",
    "verifique seu endereço de e-mail", "clique para confirmar sua identidade",
    "autenticação pendente", "PIX não autorizado", "envio de nota fiscal",
    "recebemos uma denúncia", "acesso irregular identificado",
    "atividade incomum detectada", "sistema de verificação",
    "mensagem importante sobre sua conta", "confirmação pendente",
    "ação obrigatória", "seu acesso está restrito",
    "notificação oficial", "documento anexo", "resposta obrigatória"
]

# Domínios de encurtadores de URL conhecidos (você pode expandir esta lista)
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "rebrand.ly", "is.gd",
    "buff.ly", "cutt.ly", "s.id", "adf.ly", "sh.st", "shorte.st", "t2m.io",
    "b.link", "zws.im" 
]

# Pontuações de risco para cada indicador
RISK_SCORES = {
    "dmarc_fail": 50,
    "spf_fail": 30,
    "dkim_fail": 30,
    "mismatched_url": 60, # Texto do link diferente do URL real
    "suspicious_domain_in_url": 50, # URL apontando para domínio suspeito
    "url_shortener": 20,
    "urgent_subject": 40, # AUMENTADO de 25 para 40
    "suspicious_keyword_in_subject": 20, # AUMENTADO de 15 para 20
    "generic_greeting": 15,
    "spelling_grammar_errors": 30, # Difícil de detectar sem ML ou biblioteca NLP robusta
    "urgent_call_to_action": 25,
    "unexpected_attachment_type": 70, # Ex: .exe, .zip (se não esperado)
    "suspicious_sender_domain": 40, # Ex: microsoftt.com em vez de microsoft.com
    "sender_display_name_spoofing": 35, # Display name é "Banco XYZ", mas email é spam@gmail.com
}

# Tipos de arquivos de anexo considerados de alto risco por padrão
HIGH_RISK_ATTACHMENT_TYPES = [
    'application/x-msdownload',  # .exe
    'application/x-sh',          # .sh
    'application/x-bat',         # .bat
    'application/zip',           # .zip (pode conter malwares)
    'application/x-zip-compressed',
    'application/vnd.ms-cab-compressed', # .cab
    'application/x-stuffit',     # .sit
    'application/x-rar-compressed', # .rar
    'application/x-tar',         # .tar
    'application/vnd.microsoft.portable-executable', # .dll
    'application/javascript',    # .js
    'text/javascript',
    'text/html',                 # HTML (pode conter scripts maliciosos ou phishing)
    'application/msword',        # .doc (se contiver macros)
    'application/vnd.ms-excel',  # .xls (se contiver macros)
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', # .docx (se contiver macros)
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', # .xlsx (se contiver macros)
    # Lista mais completa de tipos de arquivo perigosos pode ser encontrada online
]

def analyze_email_for_phishing(raw_email_content):
    """
    Analisa o conteúdo bruto de um e-mail em busca de indicadores de phishing.
    Retorna um dicionário com a pontuação de risco e os indicadores detectados.
    """
    analysis_results = {
        "risk_score": 0,
        "indicators": [],
        "suspicious": False
    }

    try:
        # Parse o e-mail usando a biblioteca 'email'
        # policy.default é bom para e-mails comuns
        msg = email.message_from_string(raw_email_content, policy=policy.default)

        # --- 1. Análise de Cabeçalhos ---
        sender_email = msg['From']
        subject = msg['Subject']
        authentication_results = msg.get('Authentication-Results', '')

        # DMARC/SPF/DKIM
        if "dmarc=fail" in authentication_results.lower():
            analysis_results["risk_score"] += RISK_SCORES["dmarc_fail"]
            analysis_results["indicators"].append("DMARC falhou")
        if "spf=fail" in authentication_results.lower():
            analysis_results["risk_score"] += RISK_SCORES["spf_fail"]
            analysis_results["indicators"].append("SPF falhou")
        if "dkim=fail" in authentication_results.lower():
            analysis_results["risk_score"] += RISK_SCORES["dkim_fail"]
            analysis_results["indicators"].append("DKIM falhou")
        
        # Análise do domínio do remetente
        sender_match = re.search(r'<([^>]+)>', sender_email)
        actual_sender_address = sender_match.group(1) if sender_match else sender_email
        sender_domain = actual_sender_address.split('@')[-1].lower()

        # Simple check for common spoofing (e.g., paypal.com vs paypa1.com)
        # Requires a list of known legitimate domains, which is hard to maintain.
        # For a basic check, we can look for suspicious variations or generic domains.
        # This is a placeholder for a more advanced check.
        if "gmail.com" in sender_domain and not "gmail.com" in actual_sender_address: # Example: Display name says "Google" but email is from random@gmail.com
             analysis_results["risk_score"] += RISK_SCORES["sender_display_name_spoofing"]
             analysis_results["indicators"].append(f"Spoofing de nome de exibição do remetente detectado: {sender_email}")
        
        # --- 2. Análise do Assunto ---
        if subject:
            subject_lower = subject.lower()
            if any(keyword in subject_lower for keyword in ["urgente", "ação necessária", "bloqueada", "suspensa", "expirou", "imediatamente"]): # Adicionado "imediatamente"
                analysis_results["risk_score"] += RISK_SCORES["urgent_subject"]
                analysis_results["indicators"].append("Assunto com senso de urgência/ameaça")
            if any(keyword in subject_lower for keyword in SUSPICIOUS_KEYWORDS): 
                analysis_results["risk_score"] += RISK_SCORES["suspicious_keyword_in_subject"]
                analysis_results["indicators"].append("Palavra-chave suspeita no assunto")

        # --- 3. Análise do Corpo e Links ---
        email_body_html = ""
        email_body_plain = ""
        
        # Iterar sobre as partes do e-mail para encontrar o corpo (HTML e Plain Text) e anexos
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            if ctype == 'text/plain' and 'attachment' not in cdispo:
                email_body_plain += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
            elif ctype == 'text/html' and 'attachment' not in cdispo:
                email_body_html += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
            elif part.is_multipart():
                continue # Pula para a próxima parte se for multipart
            else: # Tratar anexos
                filename = part.get_filename()
                if filename:
                    # Verifica o tipo MIME do anexo
                    if ctype in HIGH_RISK_ATTACHMENT_TYPES:
                        analysis_results["risk_score"] += RISK_SCORES["unexpected_attachment_type"]
                        analysis_results["indicators"].append(f"Anexo de tipo de alto risco detectado: {filename} ({ctype})")
                    elif filename.lower().endswith(('.exe', '.zip', '.js', '.vbs', '.bat', '.scr', '.jar', '.dll', '.ps1')):
                        analysis_results["risk_score"] += RISK_SCORES["unexpected_attachment_type"]
                        analysis_results["indicators"].append(f"Anexo com extensão de alto risco detectada: {filename}")


        # Análise de links no corpo HTML
        if email_body_html:
            link_pattern = re.compile(r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1(?:[^>]*?)>(.*?)<\/a>', re.IGNORECASE | re.DOTALL)
            
            for match in link_pattern.finditer(email_body_html):
                actual_url = match.group(2)
                visible_text = match.group(3)

                if actual_url:
                    parsed_actual_url = urlparse(actual_url)
                    actual_domain = parsed_actual_url.netloc

                    if any(shortener in actual_domain for shortener in URL_SHORTENERS):
                        analysis_results["risk_score"] += RISK_SCORES["url_shortener"]
                        analysis_results["indicators"].append(f"Link encurtado detectado: {actual_url}")
                    
                    #if visible_text and actual_domain:
                    #    visible_domain_guess = re.search(r'(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', visible_text)
                    #    if visible_domain_guess and visible_domain_guess.group(1).lower() not in actual_domain.lower():
                    #        analysis_results["risk_score"] += RISK_SCORES["mismatched_url"]
                    #        analysis_results["indicators"].append(f"Discrepância URL (visível vs. real) detectada: Texto='{visible_text}', Link='{actual_url}'")
                    #
                    #if actual_domain and actual_domain.lower() != sender_domain:
                    #    if any(word in actual_domain.lower() for word in ["login", "verify", "secure", "update", "bank", "account"]) and \
                    #       not any(word in actual_domain.lower() for word in ["google", "microsoft", "apple"]): 
                    #        analysis_results["risk_score"] += RISK_SCORES["suspicious_domain_in_url"]
                    #        analysis_results["indicators"].append(f"Domínio de link suspeito diferente do remetente: {actual_url}")
                        
        # Análise do corpo em texto simples (para texto, não links)
        if email_body_plain:
            if re.search(r'prezado(a)? cliente|caro(a)? usuário(a)|prezado(a)? senhor(a)?', email_body_plain.lower()):
                analysis_results["risk_score"] += RISK_SCORES["generic_greeting"] 
                analysis_results["indicators"].append("Saudação genérica detectada")
            
            if re.search(r'clique aqui para (verificar|atualizar|confirmar)|sua conta será (bloqueada|suspensa)', email_body_plain.lower()):
                analysis_results["risk_score"] += RISK_SCORES["urgent_call_to_action"]
                analysis_results["indicators"].append("Chamada para ação urgente/ameaçadora")

    except Exception as e:
        analysis_results["indicators"].append(f"Erro na análise do e-mail: {e}")
        print(f"Erro na análise de e-mail: {e}")

    # Define se o e-mail é suspeito com base na pontuação de risco
    if analysis_results["risk_score"] >= 60: # NOVO LIMITE: 60 pontos para ser "Suspeito"
        analysis_results["suspicious"] = True
        analysis_results["suspicious_level"] = "Alto" 
    elif analysis_results["risk_score"] >= 30: # NOVO LIMITE: 30 pontos para ser "Médio"
        analysis_results["suspicious_level"] = "Médio"
    else:
        analysis_results["suspicious_level"] = "Baixo"
        
    return analysis_results
