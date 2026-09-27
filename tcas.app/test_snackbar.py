import flet as ft
def main(page: ft.Page):
    def test_click(e):
        try:
            page.snack_bar = ft.SnackBar(ft.Text("Hello"))
            page.snack_bar.open = True
            page.update()
            print("Snackbar worked")
        except Exception as err:
            import traceback
            traceback.print_exc()
            print("Snackbar failed")
            page.add(ft.Text(f"Error: {err}"))
            page.update()
        
    page.add(ft.ElevatedButton("Test", on_click=test_click))
    
ft.app(target=main)
