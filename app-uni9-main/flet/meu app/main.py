import flet as ft
from views.welcome import welcome_view
from views.signup import signup_view
from views.create_account import create_account_view
from views.dashboard import dashboard_view

def main(page: ft.Page):
    page.title = "Phishing Analyzer" # Nome mais descritivo
    page.bgcolor = "#F8F8F8"
    page.window.width = 450
    page.window.height = 750
    page.window.maximizable = False
    page.window.resizable = False

    page.fonts = {
        "MinhaFonte": "assets/Montserrat-Regular.ttf",
        "FonteNomeApp": "assets/Outfit-Medium.ttf"
    }

    page.theme = ft.Theme(font_family="MinhaFonte")
    page.snack_bar = ft.SnackBar(ft.Text(""), open=False) # Inicializa o SnackBar uma vez

    def route_change(route):
        page.views.clear() # Limpa as views existentes

        if page.route == "/":
            page.views.append(welcome_view(page))
        elif page.route == "/signup":
            page.views.append(signup_view(page))
        elif page.route == "/create_account": # Rota para a tela de criar conta
            page.views.append(create_account_view(page))
        elif page.route == "/dashboard":
            page.views.append(dashboard_view(page))
        
        page.update()

    page.on_route_change = route_change
    # Define a rota inicial para '/' se a página não tiver uma rota definida
    if page.route == "":
        page.go("/")
    else:
        page.go(page.route) # Vai para a rota atual se já houver uma

ft.app(target=main)
