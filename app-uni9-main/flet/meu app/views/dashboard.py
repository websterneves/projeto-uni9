import flet as ft
import requests  
import webbrowser 
import config   

def dashboard_view(page: ft.Page):

    def go_back(e):

        from .welcome import welcome_view
        page.views.pop() 
        page.go("/") 

    def check_gmail_auth_status(e=None): 
        """
        Verifica o status da autenticação do Gmail com o backend.
        Totalmente síncrona, pode congelar a UI durante a requisição.
        """
        status_message_text.value = "Verificando conexão com o Gmail..."
        status_message_text.color = "#BDBDBD" 
        connect_gmail_button.visible = False
        analyze_emails_button.visible = False
        loading_indicator_analysis.visible = True
        gmail_api_error_text.visible = False
        messages_display_column.controls.clear()
        page.update() 

        user_id = page.session.get("logged_in_user_id")
        if not user_id:
            status_message_text.value = "Usuário não logado. Por favor, faça login."
            status_message_text.color = "#F44336" 
            loading_indicator_analysis.visible = False
            page.update()
            return

        try:
           
            response = requests.get(f"{config.FLASK_BACKEND_URL}/api/gmail/connect-or-check?user_id={user_id}", timeout=10)
            response.raise_for_status() 
            result = response.json()

            if result.get("authenticated"):
                status_message_text.value = f"Conectado ao Gmail como {user_id}."
                status_message_text.color = "#4CAF50"
                analyze_emails_button.visible = True
                connect_gmail_button.visible = False 

                analyze_emails_button.on_click = analyze_gmail_emails 
            else:
                status_message_text.value = "Não conectado ao Gmail. Clique para autorizar."
                status_message_text.color = "#FFC107"
                connect_gmail_button.visible = True
                analyze_emails_button.visible = False 
                

                auth_url = result.get("authorization_url")
                if auth_url:

                    connect_gmail_button.on_click = lambda e: webbrowser.open(auth_url)
                else:
                    status_message_text.value = "Erro: URL de autorização não fornecida pelo backend."
                    status_message_text.color = "#F44336" 

        except requests.exceptions.RequestException as req_err:

            status_message_text.value = f"Erro de conexão com o backend: {req_err}. Verifique se o servidor Flask está rodando em {config.FLASK_BACKEND_URL}."
            status_message_text.color = "#DC2626" 
            connect_gmail_button.visible = True 
            analyze_emails_button.visible = False
        except Exception as e:

            status_message_text.value = f"Erro inesperado ao verificar status do Gmail: {e}"
            status_message_text.color = "#F44336" 
            connect_gmail_button.visible = True 
            analyze_emails_button.visible = False
        finally:
            loading_indicator_analysis.visible = False
            page.update() 

    def analyze_gmail_emails(e):
        """
        Busca e exibe mensagens de e-mail suspeitas do Gmail através do backend.
        Totalmente síncrona, pode congelar a UI durante a requisição.
        """
        messages_display_column.controls.clear() 
        gmail_api_error_text.visible = False
        loading_indicator_analysis.visible = True
        status_message_text.value = "Analisando e-mails em busca de phishing..."
        status_message_text.color = "#2196F3" 
        page.update() 

        user_id = page.session.get("logged_in_user_id")
        if not user_id:
            status_message_text.value = "Erro: Usuário não logado."
            status_message_text.color = "#F44336" # Vermelho (RED_500)
            loading_indicator_analysis.visible = False
            page.update()
            return
        
        try:

            response = requests.get(f"{config.FLASK_BACKEND_URL}/api/gmail/analyze-messages?user_id={user_id}", timeout=120) # Aumenta o tempo limite para análises mais longas
            response.raise_for_status()
            result = response.json()

            suspicious_messages = result.get("messages", [])

            if not suspicious_messages:
                messages_display_column.controls.append(
                    ft.Text("Nenhuma mensagem suspeita encontrada nas últimas análises.", color="#4CAF50") 
                )
                status_message_text.value = "Análise concluída. Nenhuma ameaça detectada."
                status_message_text.color = "#4CAF50" 
            else:
                messages_display_column.controls.append(
                    ft.Text(f"Atenção: {len(suspicious_messages)} mensagem(ns) suspeita(s) encontrada(s):", color="#FF5722", weight=ft.FontWeight.BOLD) 
                )
              
                for msg in suspicious_messages:
                    indicators_list = ", ".join(msg.get("indicators", []))
                    messages_display_column.controls.append(
                        ft.Card(
                            content=ft.Container(
                                padding=10,
                                bgcolor="#212121",
                                border_radius=ft.border_radius.all(8),
                                content=ft.Column([
                                    ft.Text(f"De: {msg.get('from', 'N/A')}", weight=ft.FontWeight.BOLD, color="white"), 
                                    ft.Text(f"Assunto: {msg.get('subject', 'N/A')}", color="#BDBDBD"), 
                                    ft.Text(f"Nível de Risco: {msg.get('suspicious_level', 'Baixo')} (Pontuação: {msg.get('risk_score', 0)})", 
                                            color="#D32F2F" if msg.get('suspicious_level') == 'Alto' else "#FB8C00"), 
                                    ft.Text(f"Indicadores: {indicators_list if indicators_list else 'Nenhum específico'}", color="#757575", size=12), 
                                    ft.Text(f"ID: {msg.get('id', 'N/A')}", color="#9E9E9E", size=10) 
                                ])
                            ),
                            margin=ft.margin.symmetric(vertical=5),
                            elevation=3,
                        )
                    )
                status_message_text.value = "Análise concluída. Verifique as mensagens suspeitas."
                status_message_text.color = "#F44336" 

        except requests.exceptions.RequestException as req_err:
            
            gmail_api_error_text.value = f"Erro de conexão ou resposta do backend: {req_err}"
            gmail_api_error_text.visible = True
            status_message_text.value = "Erro na análise. Verifique a conexão do backend."
            status_message_text.color = "#F44336" 
        except Exception as e:
            
            gmail_api_error_text.value = f"Erro inesperado durante a análise: {e}"
            gmail_api_error_text.visible = True
            status_message_text.value = "Erro inesperado na análise de e-mails."
            status_message_text.color = "#F44336" 
        finally:
            loading_indicator_analysis.visible = False
            page.update() 

    # --- CONTROLES DE UI (DEFINIDOS APÓS AS FUNÇÕES) ---
    status_message_text = ft.Text("Verificando conexão com o Gmail...", color="#BDBDBD", size=16) 
    
    connect_gmail_button = ft.ElevatedButton("Conectar Gmail", visible=False, on_click=check_gmail_auth_status)
    analyze_emails_button = ft.ElevatedButton("Analisar E-mails", visible=False, on_click=analyze_gmail_emails)
    
    refresh_status_button = ft.ElevatedButton("Atualizar Status", on_click=check_gmail_auth_status, visible=True)

    messages_display_column = ft.Column([], scroll=ft.ScrollMode.ADAPTIVE, expand=True)

    loading_indicator_analysis = ft.ProgressRing(width=20, height=20, stroke_width=2, visible=False)

    gmail_api_error_text = ft.Text("", color="#F44336", size=14, visible=False)

    check_gmail_auth_status()

    page.on_app_resume = check_gmail_auth_status


    return ft.View(
        "/dashboard",
        [
            ft.AppBar(
                leading=ft.IconButton(
                    icon=ft.icons.ARROW_BACK if hasattr(ft, 'icons') else "arrow_back",
                    on_click=go_back,
                    icon_color="white"
                ),
                title=ft.Text("Dashboard de Phishing", color="white"),
                bgcolor="#1E1E1E", 
                center_title=True
            ),
            
            ft.Container(
                content=ft.Column(
                    [
                        ft.Text("Bem-vindo ao Dashboard de Análise de E-mails!", size=24, weight="bold", color="white"),
                        ft.Divider(color="#424242"),

                        status_message_text, 
                        loading_indicator_analysis, 
                        
                        ft.Row(
                            [
                                connect_gmail_button, 
                                analyze_emails_button,
                                refresh_status_button,
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                            spacing=15
                        ),
                        gmail_api_error_text, 
                        
                        ft.Divider(color="#424242"), 
                        ft.Text("Resultados da Análise de E-mails:", size=18, weight="bold", color="white"),
                        messages_display_column,

                    ],
                    alignment=ft.MainAxisAlignment.START,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=15,
                ),
                padding=20,
                alignment=ft.alignment.top_center,
                expand=True
            )
        ],
        bgcolor="#121212", 
        padding=0,
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        scroll=ft.ScrollMode.ADAPTIVE
    )
