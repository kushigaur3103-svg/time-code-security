import flet as ft
def main(page: ft.Page):
    import time
    time.sleep(1)
    res = page.shared_preferences.set('test', '123')
    print("RES:", type(res))
    page.window.destroy()

ft.app(target=main)
