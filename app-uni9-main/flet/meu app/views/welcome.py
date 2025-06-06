import flet as ft

def welcome_view(page: ft.Page):
    def go_to_signup(e):
        page.go("/signup")

    def go_to_create_account(e):
        page.go("/create_account") # Rota atualizada para /create_account
    
    def login_sso(e):
        page.snack_bar = ft.SnackBar(
            content=ft.Text("Funcionalidade SSO não implementada ainda!"),
            bgcolor=ft.colors.ORANGE_700
        )
        page.snack_bar.open = True
        page.update()


    return ft.View(
        "/", [
            ft.Container(
                content=ft.Column(
                    [
                        ft.Image(
                            src="assets/phishing.png",
                            width=230,
                            height=230
                        ),
                        ft.Text(
                            "Phishing Analyzer", # Nome do App atualizado
                            size=44,
                            weight=ft.FontWeight.BOLD,
                            font_family="FonteNomeApp"
                        ),
                        ft.Column(
                            controls=[],
                            height=35,
                        ),
                        ft.ElevatedButton(
                            "ENTRAR", 
                            on_click=go_to_signup, 
                            bgcolor="green", 
                            color="white",
                            width=200,
                            height=50,
                        ),
                        ft.ElevatedButton(
                            "CRIAR CONTA", 
                            on_click=go_to_create_account, 
                            bgcolor="blue", 
                            color="white",
                            width=200,
                            height=50,
                        ),
                        ft.Text("Login SSO:", color="gray", size=13),
                        ft.Container(
                            content=ft.Image(
                                src="assets/e-learning-svgrepo-com.svg",
                                width=40,
                                height=40
                            ),
                            on_click=login_sso,
                            border_radius=10,
                            padding=5,
                            ink=True
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
