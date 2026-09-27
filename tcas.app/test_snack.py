import flet as ft
def main(page: ft.Page):
    try:
        page.snack_bar = ft.SnackBar(ft.Text('hi'))
        page.snack_bar.open = True
        page.update()
        print("Success snack_bar")
    except Exception as e:
        print("Exception snack_bar:", e)
    
    try:
        page.overlay.append(ft.SnackBar(ft.Text('hi2')))
        print("Success overlay")
    except Exception as e:
        print("Exception overlay:", e)

    page.window.destroy()

ft.app(target=main)
