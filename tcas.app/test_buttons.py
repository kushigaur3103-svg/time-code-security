import flet as ft
from main import main

class MockPage:
    def __init__(self):
        self.title = ""
        self.bgcolor = ""
        self.vertical_alignment = None
        self.horizontal_alignment = None
        self.theme_mode = None
        self.controls = []
        self.snack_bar = None
    
    def add(self, *controls):
        self.controls.extend(controls)
        
    def update(self):
        pass

page = MockPage()
main(page)

# Find the login and signup buttons
login_btn = None
signup_btn = None
email_fld = None
pass_fld = None

for c in page.controls:
    if isinstance(c, ft.ElevatedButton):
        login_btn = c
    elif isinstance(c, ft.OutlinedButton):
        signup_btn = c
    elif isinstance(c, ft.TextField) and c.label == "Email":
        email_fld = c
    elif isinstance(c, ft.TextField) and c.label == "Password":
        pass_fld = c

email_fld.value = "test@test.com"
pass_fld.value = "password123"

try:
    login_btn.on_click(None)
    print("Login button click executed successfully.")
except Exception as e:
    import traceback
    traceback.print_exc()

try:
    signup_btn.on_click(None)
    print("Signup button click executed successfully.")
except Exception as e:
    import traceback
    traceback.print_exc()
