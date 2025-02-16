from pfx import get_certificate, authenticate
from nicegui import app, ui, events
import hashlib
import base64
import os


@ui.page("/")
def index():
    if not app.storage.user.get("authenticated", False):
        ui.navigate.to("/login")
    ui.label(f"Welcome {app.storage.user.get('username')}")
    

@ui.page("/login")
def login():
    def show_error(msg: str) -> None:
        error.classes(remove="hidden")
        error.text = msg
    
    def handle_cert_upload(e: events.UploadEventArguments):
        cert = e.content.read()
        app.storage.user["cert"] = base64.b64encode(cert).decode()
    
    def try_login() -> None:
        if not username.value and not password.value:
            show_error("Missing user or password")
            return False
        elif username.value not in app.storage.general["users"]:
            show_error("Unknown user / password or invalid certificate")
            return False
        elif hashlib.sha256(base64.b64decode(app.storage.user["cert"])).hexdigest() != app.storage.general["users"][username.value]:
            show_error("Unknown user / password or invalid certificate")
            return False
        elif not authenticate(password.value, base64.b64decode(app.storage.user["cert"])):
            show_error("Error decrypting certificate")
        else:
            app.storage.user["authenticated"] = True
            app.storage.user["username"] = username.value
            ui.navigate.to("/")

    with ui.card().classes("absolute-center"):
        ui.label("Username")
        username = ui.input("Username").classes("w-full")
        ui.label("Password")
        password = ui.input("Password", password=True, password_toggle_button=True).classes("w-full")
        ui.upload(label="PFX Certificate", auto_upload=True, on_upload=handle_cert_upload).props("accept=.pfx")
        with ui.row():
            ui.button("Login", on_click=try_login)
            ui.link("Click to register...", "/register")
        error = ui.label().classes("hidden text-red")


@ui.page("/register")
def register():
    def register_user():
        certificate = get_certificate(username.value, password.value)
        app.storage.general["users"][username.value] = hashlib.sha256(certificate).hexdigest()
        ui.download(certificate, f"{username.value}.pfx")
        register_button.classes(add="hidden")
        login_button.classes(remove="hidden")

    with ui.card().classes("absolute-center"):
        ui.label("Username")
        username = ui.input("Username").classes("w-full")
        ui.label("Password")
        password = ui.input("Password", password=True, password_toggle_button=True).classes("w-full")
        with ui.row():
            register_button = ui.button("Register", on_click=register_user)
            login_button = ui.button("Login", on_click=lambda: ui.navigate.to("/login")).classes("hidden")
            ui.link("Click to login...", "/login")
    

if __name__ in {"__main__", "__mp_main__"}:
    app.storage.general["users"] = {}
    ui.run(dark=True, storage_secret=os.urandom(128))
