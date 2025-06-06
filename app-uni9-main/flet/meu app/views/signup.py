import flet as ft
import requests # Importar a biblioteca requests para fazer requisições HTTP
import json # Importar json para trabalhar com dados JSON
import config # Importa as configurações do nosso arquivo config.py
# O módulo asyncio e a classe MockErrorResponse não são mais necessários,
# pois a requisição HTTP será feita de forma síncrona e direta.

def signup_view(page: ft.Page): # Renomeado para signup_view para refletir o uso como tela de login
    # Campo de texto para exibir mensagens de erro gerais da API
    api_message_text = ft.Text("", color="#F44336", size=14, visible=False)

    def go_to_welcome(e):
        page.views.pop()
        page.go("/")

    # Função de login agora totalmente SÍNCRONA
    # Todas as operações de UI (habilitar/desabilitar botão, mostrar indicador, etc.)
    # e a chamada HTTP serão feitas na mesma thread de execução.
    def perform_login(e):
        # Limpar mensagens de erro anteriores e erros de validação
        api_message_text.visible = False
        api_message_text.value = ""
        username_field.error_text = None
        password_field.error_text = None
        terms_error.visible = False

        username_value = username_field.value.strip()
        password_value = password_field.value.strip()
        terms_accepted = terms_checkbox.value

        error = False
        
        # Validações locais (Frontend)
        if not username_value:
            username_field.error_text = "Usuário é obrigatório"
            error = True
            
        if not password_value:
            password_field.error_text = "Senha é obrigatória"
            error = True
            
        if not terms_accepted:
            terms_error.visible = True
            error = True
        
        page.update() # Atualiza para mostrar os erros de validação locais
        
        if error:
            return # Se houver erros locais, não prossegue para a API

        # Se as validações locais passarem, tenta logar via API
        try:
            # Desabilita o botão e mostra o indicador de carregamento
            login_button.disabled = True
            loading_indicator.visible = True
            page.update() # Atualiza a UI para refletir essas mudanças

            # Verifica se FLASK_BACKEND_URL está definido em config.py
            if not hasattr(config, 'FLASK_BACKEND_URL'):
                api_message_text.value = "Erro de configuração: 'FLASK_BACKEND_URL' não encontrado em config.py."
                api_message_text.color = "#DC2626"
                api_message_text.visible = True
                page.update()
                return

            payload = {
                "user": username_value,
                "senha": password_value
            }
            
            # Chamada síncrona direta ao backend Flask.
            # Esta linha pode causar um congelamento temporário da UI
            # enquanto aguarda a resposta do servidor.
            response = requests.post(f"{config.FLASK_BACKEND_URL}/login", json=payload, timeout=10)
            
            # Levanta um HTTPError para códigos de status 4xx/5xx
            response.raise_for_status() 

            result = response.json()
            
            if response.status_code == 200:
                # Login bem-sucedido! Armazena o user_id retornado pelo backend na sessão
                logged_in_user_id = result.get('user_id')
                page.session.set("logged_in_user_id", logged_in_user_id) # Armazena na sessão do Flet
                
                # Limpa os campos do formulário (opcional)
                username_field.value = ""
                password_field.value = ""
                terms_checkbox.value = False

                # Navega diretamente para o dashboard
                page.go("/dashboard") 

            else:
                # Caso o backend retorne um erro 4xx, mas sem lançar exceção (ex: 401)
                # Exibe a mensagem de erro da API
                api_message_text.value = result.get('erro', 'Erro desconhecido ao fazer login.')
                api_message_text.color = "#F44336" # Vermelho para erro
                api_message_text.visible = True
                page.update() # Atualiza para mostrar a mensagem de erro

        except requests.exceptions.RequestException as req_err:
            # Captura erros de conexão, timeout, ou status HTTP 4xx/5xx lançados por raise_for_status()
            api_message_text.value = f"Erro de conexão com o servidor: {req_err}. Verifique se o backend Flask está rodando em {config.FLASK_BACKEND_URL}."
            api_message_text.color = "#DC2626" # Vermelho mais forte para erros de conexão
            api_message_text.visible = True
            page.update() # Atualiza para mostrar a mensagem de erro
            print(f"Erro de conexão no login: {req_err}")
        except Exception as ex:
            # Captura quaisquer outras exceções inesperadas
            api_message_text.value = f"Erro inesperado: {ex}"
            api_message_text.color = "#DC2626" # Vermelho mais forte para erros inesperados
            api_message_text.visible = True
            page.update() # Atualiza para mostrar a mensagem de erro
            print(f"Erro inesperado no login: {ex}")
        finally:
            # Garante que o botão e o indicador voltem ao normal, mesmo em caso de erro
            login_button.disabled = False
            loading_indicator.visible = False
            page.update() # Atualiza para reativar o botão e esconder o indicador

    # Definição dos campos de texto, checkbox e botões (mantido o mesmo)
    username_field = ft.TextField(
        label="Usuário", 
        width=330,
        autofocus=True,
        content_padding=ft.padding.symmetric(vertical=10, horizontal=12)
    )
    
    password_field = ft.TextField(
        label="Senha",
        password=True,
        can_reveal_password=True,
        width=330,
        content_padding=ft.padding.symmetric(vertical=10, horizontal=12),
    )
    
    terms_checkbox = ft.Checkbox(
        label="Aceito os termos de privacidade", 
        value=False
    )
    
    terms_error = ft.Text(
        "Você deve aceitar os termos de privacidade",
        color="red", 
        size=12,
        visible=False
    )

    loading_indicator = ft.ProgressRing(width=20, height=20, stroke_width=2, visible=False)

    login_button = ft.ElevatedButton(
        "Entrar", 
        width=200, 
        height=50, 
        bgcolor="green", 
        color="white",
        on_click=perform_login, # Chamada da função síncrona
    )

    return ft.View(
        "/signup", [
            ft.Container(
                content=ft.Column(
                    [
                        ft.Image(src=f"assets/phishing.png", width=110, height=110),
                        ft.Container(
                            content=ft.Text("Login", size=30, weight="bold", text_align=ft.TextAlign.CENTER),
                            padding=ft.padding.only(bottom=30)
                        ),
                        api_message_text, # Mensagem de erro da API
                        username_field,
                        password_field,
                        ft.Container(height=5),
                        ft.Container(
                            content=ft.Switch(label="Manter Login", scale=0.9),
                            alignment=ft.alignment.center_left,
                            padding=ft.padding.only(left=15)
                        ),
                        ft.Container(
                            content=ft.Column([
                                terms_checkbox,
                                terms_error
                            ], spacing=0),
                            alignment=ft.alignment.center_left,
                            padding=ft.padding.only(left=23)
                        ),
                        ft.Container(
                            content=ft.Row(
                                [
                                    login_button,
                                    loading_indicator,
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                spacing=10
                            ),
                            padding=ft.padding.only(top=23),
                        ),
                        ft.Container(
                            content=ft.TextButton(
                                "Esqueceu a senha?",
                                on_click=lambda e: print("Redirecionar para recuperação de senha"),
                                style=ft.ButtonStyle(
                                    padding=ft.padding.all(0),
                                    shape=ft.RoundedRectangleBorder(radius=0),
                                    bgcolor=None
                                ),
                            ),
                            alignment=ft.alignment.center,
                            padding=ft.padding.only(top=0),
                        ),
                        ft.Container(
                            content=ft.IconButton(
                                icon=ft.icons.ARROW_BACK if hasattr(ft, 'icons') else "arrow_back", 
                                on_click=go_to_welcome,
                                bgcolor="transparent", 
                                icon_color="white", 
                                icon_size=30,
                            ),
                            padding=ft.padding.only(left=10),
                            alignment=ft.alignment.center_left
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER, 
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER, 
                ),
                alignment=ft.alignment.center,
                expand=True,
            )
        ],
        padding=20,
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
    )
