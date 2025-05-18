import customtkinter as ctk
from src.gui.main_window import MainWindow

if __name__ == "__main__":
    ctk.set_appearance_mode("Light")  # Set default to Light mode
    root = ctk.CTk()
    app = MainWindow(root)
    root.mainloop()