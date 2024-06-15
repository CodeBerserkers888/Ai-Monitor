import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import subprocess

def create_gui():
    # Funkcja do wywoływania skanowania antywirusowego
    def run_antivirus_scan():
        if scan_var.get():
            try:
                subprocess.run(["powershell", "Start-MpScan -ScanType QuickScan"], check=True)
                messagebox.showinfo("Skanowanie antywirusowe", "Skanowanie zakończone pomyślnie!")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Błąd", f"Wystąpił błąd podczas skanowania: {e}")
        else:
            messagebox.showinfo("Skanowanie antywirusowe", "Skanowanie nie zostało uruchomione.")

    # Tworzenie głównego okna
    root = tk.Tk()
    root.title("Monitoring AI")

    # Ładowanie logo
    logo_path = "assets/LogoMonitoringAI.png"
    logo_image = Image.open(logo_path)
    logo_image = logo_image.resize((100, 100), Image.ANTIALIAS)  # Zmiana rozmiaru logo, jeśli konieczne
    logo_photo = ImageTk.PhotoImage(logo_image)

    # Dodawanie logo do GUI w rogu
    logo_label = tk.Label(root, image=logo_photo)
    logo_label.image = logo_photo
    logo_label.place(x=10, y=10)

    # Dodawanie informacji o prawach autorskich
    copyright_text = "Copyright © CodeBerserkers888 - Github"
    copyright_label = tk.Label(root, text=copyright_text)
    copyright_label.pack(side="bottom")

    # Checkbox do wyboru skanowania antywirusowego
    scan_var = tk.BooleanVar()
    scan_checkbox = tk.Checkbutton(root, text="Uruchom skanowanie antywirusowe", variable=scan_var)
    scan_checkbox.pack()

    # Przycisk do uruchamiania funkcji skanowania
    scan_button = tk.Button(root, text="Uruchom skanowanie", command=run_antivirus_scan)
    scan_button.pack()

    # Uruchomienie GUI
    root.mainloop()

if __name__ == "__main__":
    create_gui()
