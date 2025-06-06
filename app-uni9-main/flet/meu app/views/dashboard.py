import flet as ft
import requests  # Importar requests para chamadas HTTP síncronas
import webbrowser # Para abrir o navegador para o OAuth (se o backend retornar a URL)
import config    # Importa as configurações do nosso arquivo config.py

def dashboard_view(page: ft.Page):
    # --- FUNÇÕES (DEFINIDAS ANTES DOS CONTROLES DE UI) ---
    def go_back(e):
        # A importação do welcome_view é feita aqui para evitar importação circular
        from .welcome import welcome_view
        page.views.pop() # Remove a view atual
        page.go("/") # Volta para a rota inicial (welcome_view)

    def check_gmail_auth_status(e=None): # Adicionado e=None para compatibilidade com on_click
        """
        Verifica o status da autenticação do Gmail com o backend.
        Totalmente síncrona, pode congelar a UI durante a requisição.
        """
        status_message_text.value = "Verificando conexão com o Gmail..."
        status_message_text.color = "#BDBDBD" # Cinza (GREY_500)
        connect_gmail_button.visible = False
        analyze_emails_button.visible = False
        loading_indicator_analysis.visible = True
        gmail_api_error_text.visible = False
        messages_display_column.controls.clear() # Limpa resultados de análises anteriores
        page.update() # Atualiza a UI imediatamente para mostrar o status de carregamento

        user_id = page.session.get("logged_in_user_id")
        if not user_id:
            status_message_text.value = "Usuário não logado. Por favor, faça login."
            status_message_text.color = "#F44336" # Vermelho (RED_500)
            loading_indicator_analysis.visible = False
            page.update()
            return

        try:
            # CHAMADA HTTP SÍNCRONA ao backend Flask.
            # ATENÇÃO: Esta linha pode congelar a interface do usuário enquanto a requisição é processada.
            response = requests.get(f"{config.FLASK_BACKEND_URL}/api/gmail/connect-or-check?user_id={user_id}", timeout=10)
            response.raise_for_status() # Lança exceção para status HTTP 4xx/5xx (ex: 404, 500)
            result = response.json()

            if result.get("authenticated"):
                status_message_text.value = f"Conectado ao Gmail como {user_id}."
                status_message_text.color = "#4CAF50" # Verde (GREEN_500)
                analyze_emails_button.visible = True
                connect_gmail_button.visible = False # Garante que o botão de conexão se esconde
                # Atribui a função de análise ao botão apenas se estiver conectado
                analyze_emails_button.on_click = analyze_gmail_emails 
            else:
                status_message_text.value = "Não conectado ao Gmail. Clique para autorizar."
                status_message_text.color = "#FFC107" # Amarelo (AMBER_500)
                connect_gmail_button.visible = True
                analyze_emails_button.visible = False # Garante que o botão de análise se esconde
                
                # Ação para abrir a URL de autorização no navegador
                auth_url = result.get("authorization_url")
                if auth_url:
                    # O Flet abre a URL no navegador padrão do sistema
                    connect_gmail_button.on_click = lambda e: webbrowser.open(auth_url)
                else:
                    status_message_text.value = "Erro: URL de autorização não fornecida pelo backend."
                    status_message_text.color = "#F44336" # Vermelho (RED_500)

        except requests.exceptions.RequestException as req_err:
            # Erros de conexão (DNS, rede, timeout) ou status HTTP de erro
            status_message_text.value = f"Erro de conexão com o backend: {req_err}. Verifique se o servidor Flask está rodando em {config.FLASK_BACKEND_URL}."
            status_message_text.color = "#DC2626" # Vermelho mais forte
            connect_gmail_button.visible = True # Oferece a opção de tentar conectar novamente
            analyze_emails_button.visible = False
        except Exception as e:
            # Captura qualquer outro erro inesperado
            status_message_text.value = f"Erro inesperado ao verificar status do Gmail: {e}"
            status_message_text.color = "#F44336" # Vermelho (RED_500)
            connect_gmail_button.visible = True # Oferece a opção de tentar conectar novamente
            analyze_emails_button.visible = False
        finally:
            loading_indicator_analysis.visible = False
            page.update() # Garante que a UI é atualizada no final da operação

    def analyze_gmail_emails(e):
        """
        Busca e exibe mensagens de e-mail suspeitas do Gmail através do backend.
        Totalmente síncrona, pode congelar a UI durante a requisição.
        """
        messages_display_column.controls.clear() # Limpa os resultados anteriores
        gmail_api_error_text.visible = False
        loading_indicator_analysis.visible = True
        status_message_text.value = "Analisando e-mails em busca de phishing..."
        status_message_text.color = "#2196F3" # Azul (BLUE_500)
        page.update() # Atualiza a UI imediatamente para mostrar o status de carregamento

        user_id = page.session.get("logged_in_user_id")
        if not user_id:
            status_message_text.value = "Erro: Usuário não logado."
            status_message_text.color = "#F44336" # Vermelho (RED_500)
            loading_indicator_analysis.visible = False
            page.update()
            return
        
        try:
            # CHAMADA HTTP SÍNCRONA ao backend para analisar e-mails.
            # ATENÇÃO: Esta linha pode congelar a interface do usuário, especialmente para análises longas.
            response = requests.get(f"{config.FLASK_BACKEND_URL}/api/gmail/analyze-messages?user_id={user_id}", timeout=120) # Aumenta o tempo limite para análises mais longas
            response.raise_for_status()
            result = response.json()

            suspicious_messages = result.get("messages", [])

            if not suspicious_messages:
                messages_display_column.controls.append(
                    ft.Text("Nenhuma mensagem suspeita encontrada nas últimas análises.", color="#4CAF50") # Verde (GREEN_500)
                )
                status_message_text.value = "Análise concluída. Nenhuma ameaça detectada."
                status_message_text.color = "#4CAF50" # Verde (GREEN_500)
            else:
                messages_display_column.controls.append(
                    ft.Text(f"Atenção: {len(suspicious_messages)} mensagem(ns) suspeita(s) encontrada(s):", color="#FF5722", weight=ft.FontWeight.BOLD) # Laranja A700
                )
                # Itera sobre as mensagens suspeitas e cria um Card para cada uma
                for msg in suspicious_messages:
                    indicators_list = ", ".join(msg.get("indicators", []))
                    messages_display_column.controls.append(
                        ft.Card(
                            content=ft.Container(
                                padding=10,
                                bgcolor="#212121", # Cinza escuro (GREY_900) - Cor de fundo do card
                                border_radius=ft.border_radius.all(8),
                                content=ft.Column([
                                    ft.Text(f"De: {msg.get('from', 'N/A')}", weight=ft.FontWeight.BOLD, color="white"), 
                                    ft.Text(f"Assunto: {msg.get('subject', 'N/A')}", color="#BDBDBD"), # Cinza (GREY_500)
                                    ft.Text(f"Nível de Risco: {msg.get('suspicious_level', 'Baixo')} (Pontuação: {msg.get('risk_score', 0)})", 
                                            color="#D32F2F" if msg.get('suspicious_level') == 'Alto' else "#FB8C00"), # Vermelho 700 ou Laranja 700
                                    ft.Text(f"Indicadores: {indicators_list if indicators_list else 'Nenhum específico'}", color="#757575", size=12), # Cinza 700
                                    ft.Text(f"ID: {msg.get('id', 'N/A')}", color="#9E9E9E", size=10) # Cinza 400
                                ])
                            ),
                            margin=ft.margin.symmetric(vertical=5),
                            elevation=3,
                        )
                    )
                status_message_text.value = "Análise concluída. Verifique as mensagens suspeitas."
                status_message_text.color = "#F44336" # Vermelho (RED_500)

        except requests.exceptions.RequestException as req_err:
            # Erros de conexão ou status HTTP de erro do backend
            gmail_api_error_text.value = f"Erro de conexão ou resposta do backend: {req_err}"
            gmail_api_error_text.visible = True
            status_message_text.value = "Erro na análise. Verifique a conexão do backend."
            status_message_text.color = "#F44336" # Vermelho (RED_500)
        except Exception as e:
            # Captura qualquer outro erro inesperado
            gmail_api_error_text.value = f"Erro inesperado durante a análise: {e}"
            gmail_api_error_text.visible = True
            status_message_text.value = "Erro inesperado na análise de e-mails."
            status_message_text.color = "#F44336" # Vermelho (RED_500)
        finally:
            loading_indicator_analysis.visible = False
            page.update() # Garante que a UI é atualizada no final da operação

    # --- CONTROLES DE UI (DEFINIDOS APÓS AS FUNÇÕES) ---
    # Campo de texto para exibir mensagens de status da conexão Gmail ou análise
    status_message_text = ft.Text("Verificando conexão com o Gmail...", color="#BDBDBD", size=16) # Cinza (GREY_500)
    
    # Botões para interação com o Gmail
    # Os on_click são definidos AQUI, APÓS as funções serem definidas
    connect_gmail_button = ft.ElevatedButton("Conectar Gmail", visible=False, on_click=check_gmail_auth_status)
    analyze_emails_button = ft.ElevatedButton("Analisar E-mails", visible=False, on_click=analyze_gmail_emails)
    
    # Botão para atualizar o status manualmente (útil se on_app_resume não pegar de primeira)
    refresh_status_button = ft.ElevatedButton("Atualizar Status", on_click=check_gmail_auth_status, visible=True)

    # Coluna para exibir as mensagens de e-mail analisadas
    messages_display_column = ft.Column([], scroll=ft.ScrollMode.ADAPTIVE, expand=True)

    # Indicador de carregamento para as operações de API
    loading_indicator_analysis = ft.ProgressRing(width=20, height=20, stroke_width=2, visible=False)
    
    # Campo para exibir mensagens de erro específicas da API do Gmail
    gmail_api_error_text = ft.Text("", color="#F44336", size=14, visible=False) # Vermelho (RED_500)

    # Chamada inicial para verificar o status do Gmail ao carregar a view.
    # A função é síncrona, basta chamá-la diretamente no momento da construção da view.
    check_gmail_auth_status()

    # Adiciona um listener para quando o aplicativo Flet retoma o foco
    # Isso é essencial para re-verificar o status do Gmail após o OAuth no navegador externo.
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
                bgcolor="#1E1E1E", # Cor de fundo da AppBar
                center_title=True
            ),
            
            ft.Container(
                content=ft.Column(
                    [
                        ft.Text("Bem-vindo ao Dashboard de Análise de E-mails!", size=24, weight="bold", color="white"),
                        ft.Divider(color="#424242"), # Divisor
                        
                        # --- Elementos de Análise de E-mail ---
                        status_message_text, # Status de conexão do Gmail
                        loading_indicator_analysis, # Indicador de carregamento
                        
                        ft.Row(
                            [
                                connect_gmail_button, # Botão para conectar Gmail
                                analyze_emails_button, # Botão para analisar e-mails
                                refresh_status_button, # Botão para atualizar o status manualmente
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                            spacing=15
                        ),
                        gmail_api_error_text, # Mensagens de erro da API do Gmail
                        
                        ft.Divider(color="#424242"), # Divisor
                        ft.Text("Resultados da Análise de E-mails:", size=18, weight="bold", color="white"),
                        messages_display_column, # Coluna para exibir as mensagens analisadas
                        # --- Fim dos Elementos de Análise de E-mail ---
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
        bgcolor="#121212", # Cor de fundo da View
        padding=0,
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        scroll=ft.ScrollMode.ADAPTIVE
    )
