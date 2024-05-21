import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet

class SafeData:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt(self, token):
        return self.cipher.decrypt(token).decode()

class SafeDataApp:
    def __init__(self, root):
        self.safe_data = SafeData()
        self.root = root
        self.root.title("SafeData")
        
        self.main_frame = tk.Frame(root, padx=10, pady=10)
        self.main_frame.pack(padx=10, pady=10)
        
        self.label = tk.Label(self.main_frame, text="Ingrese el dato a cifrar:")
        self.label.grid(row=0, column=0, pady=5)
        
        self.data_entry = tk.Entry(self.main_frame, width=50)
        self.data_entry.grid(row=0, column=1, pady=5)
        
        self.encrypt_button = tk.Button(self.main_frame, text="Cifrar", command=self.encrypt_data)
        self.encrypt_button.grid(row=1, column=0, columnspan=2, pady=5)
        
        self.encrypted_label = tk.Label(self.main_frame, text="Dato cifrado:")
        self.encrypted_label.grid(row=2, column=0, pady=5)
        
        self.encrypted_data = tk.Text(self.main_frame, height=4, width=50)
        self.encrypted_data.grid(row=2, column=1, pady=5)
        
        self.decrypt_button = tk.Button(self.main_frame, text="Descifrar", command=self.decrypt_data)
        self.decrypt_button.grid(row=3, column=0, columnspan=2, pady=5)
        
    def encrypt_data(self):
        data = self.data_entry.get()
        encrypted = self.safe_data.encrypt(data)
        self.encrypted_data.delete(1.0, tk.END)
        self.encrypted_data.insert(tk.END, encrypted)
        
    def decrypt_data(self):
        password = simpledialog.askstring("Contraseña", "Ingrese la contraseña:", show='*')
        if password == "mypassword":  # Reemplaza con una verificación de contraseña segura en una aplicación real
            encrypted = self.encrypted_data.get(1.0, tk.END).strip()
            try:
                decrypted = self.safe_data.decrypt(encrypted.encode())
                messagebox.showinfo("Dato Descifrado", f"El dato original es: {decrypted}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo descifrar el dato: {e}")
        else:
            messagebox.showerror("Error", "Contraseña incorrecta")

if __name__ == "__main__":
    root = tk.Tk()
    app = SafeDataApp(root)
    root.mainloop()

