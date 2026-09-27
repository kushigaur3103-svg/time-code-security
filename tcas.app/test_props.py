import flet as ft
def main(page: ft.Page):
    print("Has client_storage:", hasattr(page, "client_storage"))
    print("Has shared_preferences:", hasattr(page, "shared_preferences"))
    print("Has session:", hasattr(page, "session"))
    page.window.destroy()

ft.app(target=main)
