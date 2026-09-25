import os

def render_debug_page():
    env_str = str(os.environ)
    return "<html><body>Debug: " + env_str + "</body></html>"
