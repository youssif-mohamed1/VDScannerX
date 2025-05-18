import customtkinter as ctk

# Set global appearance and color theme
ctk.set_appearance_mode("System")  # "Light", "Dark", "System"
ctk.set_default_color_theme("blue")  # Themes: "blue", "dark-blue", "green"

# Create the main window
app = ctk.CTk()
app.title("🌟 Modern GUI Demo")
app.geometry("500x400")
app.resizable(False, False)

# Callback for button
def submit_text():
    user_input = textbox.get()
    if user_input.strip() == "":
        output_label.configure(text="⚠️ Please enter something!", text_color="red")
    else:
        output_label.configure(text=f"✅ You entered: {user_input}", text_color="green")
        progressbar.start()

# Callback for appearance toggle
def toggle_mode():
    mode = appearance_switch.get()
    ctk.set_appearance_mode("Dark" if mode else "Light")

# Title label
title_label = ctk.CTkLabel(app, text="🚀 Welcome to Modern GUI", font=ctk.CTkFont(size=20, weight="bold"))
title_label.pack(pady=(20, 10))

# Text input
textbox = ctk.CTkEntry(app, width=350, height=40, placeholder_text="Type something cool...")
textbox.pack(pady=10)

# Submit button
submit_button = ctk.CTkButton(app, text="🔍 Submit", width=200, command=submit_text)
submit_button.pack(pady=10)

# Output label
output_label = ctk.CTkLabel(app, text="", font=ctk.CTkFont(size=14))
output_label.pack(pady=10)

# Progress bar
progressbar = ctk.CTkProgressBar(app, width=300)
progressbar.set(0.5)
progressbar.pack(pady=10)

# Theme switch
appearance_switch = ctk.CTkSwitch(app, text="🌗 Dark Mode", command=toggle_mode)
appearance_switch.pack(pady=20)

# Run the app
app.mainloop()
