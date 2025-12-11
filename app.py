import tkinter as tk
from tkinter import messagebox, ttk
import os
import sys
from random import randint, choice
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip


class app:
    """
    Cleaned and fully working version of your password tool.
    - All class methods are static because you call them as app.method(...)
    - Fixed passGen window (no widgets defined in class body)
    - Fixed generatePasWithOptions wiring
    - Kept your on-disk format: <username>\n<key-bytes>\n<salt-bytes>
    - Simplified Show Records table + added Copy button
    - Cross-platform PDF opener
    """

    # ------------------------ Utility: Crypto & strength ---------------------
    @staticmethod
    def generate_key(password: str, salt: bytes | None = None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
        return key, salt

    @staticmethod
    def encrypt_data(data: str, key: bytes) -> bytes:
        fernet = Fernet(key)
        return fernet.encrypt(data.encode("utf-8"))

    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data).decode("utf-8")

    @staticmethod
    def check_password_strength(password: str):
        if len(password) < 8:
            return "Weak", "red"
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        score = sum([has_upper, has_lower, has_digit, has_special])
        if score == 4:
            return "Strong", "green"
        elif score >= 2:
            return "Medium", "orange"
        else:
            return "Weak", "red"

    # ------------------------ Navigation helpers ----------------------------
    @staticmethod
    def Return(wn):
        messagebox.showinfo("Logged Out", "You have logged out")
        wn.destroy()
        app.Main()

    @staticmethod
    def Return_to_Main(wn):
        wn.destroy()
        app.Main()

    # ------------------------ Password generation ---------------------------
    @staticmethod
    def generatePas(default_length: int = 12) -> str:
        """Generate a strong password with at least one of each type."""
        upper = string.ascii_uppercase
        lower = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()-_=+[]{}|;:,.<>?"

        # ensure one of each type if length allows
        length = max(8, int(default_length))
        password_chars = [
            choice(upper),
            choice(lower),
            choice(digits),
            choice(special),
        ]
        all_chars = upper + lower + digits + special
        for _ in range(length - 4):
            password_chars.append(choice(all_chars))
        # Fisher–Yates shuffle
        for i in range(len(password_chars) - 1, 0, -1):
            j = randint(0, i)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
        return "".join(password_chars)

    @staticmethod
    def generatePasWithOptions(length: int, tk_stringvar: tk.StringVar | None = None) -> str:
        pwd = app.generatePas(length)
        if tk_stringvar is not None:
            tk_stringvar.set(pwd)
        try:
            pyperclip.copy(pwd)
        except Exception:
            pass
        return pwd

    @staticmethod
    def copy_to_clipboard(text: str):
        try:
            pyperclip.copy(text)
            messagebox.showinfo("Success", "Copied to clipboard!")
        except Exception:
            messagebox.showerror("Error", "Could not copy to clipboard")

    # ------------------------ Windows: Password Generator -------------------
    @staticmethod
    def passGen(master):
        master.destroy()
        wn = tk.Tk()
        wn.geometry("800x600")
        wn.title("Password Generator")
        wn.configure(background="#f0f0f0")

        main_frame = tk.Frame(wn, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_frame = tk.Frame(main_frame, bg="#2c3e50", height=80)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="Password Generator", fg="white", bg="#2c3e50",
                 font=("Helvetica", 20, "bold")).pack(expand=True)

        content_frame = tk.Frame(main_frame, bg="#f0f0f0")
        content_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(content_frame,
                 text="Click the button below to generate a secure random password",
                 bg="#f0f0f0", fg="#2c3e50", font=("Helvetica", 12), wraplength=500).pack(pady=30)

        options_frame = tk.Frame(content_frame, bg="#f0f0f0")
        options_frame.pack(pady=10)

        tk.Label(options_frame, text="Password Length:", bg="#f0f0f0").grid(row=0, column=0, padx=5)
        length_var = tk.IntVar(value=12)
        length_spinbox = tk.Spinbox(options_frame, from_=8, to=64, width=5, textvariable=length_var)
        length_spinbox.grid(row=0, column=1, padx=5)

        password_var = tk.StringVar()
        tk.Entry(content_frame, textvariable=password_var, font=("Helvetica", 12),
                 state="readonly", width=30, justify="center").pack(pady=10)

        tk.Button(
            content_frame,
            text="Generate Password",
            command=lambda: app.generatePasWithOptions(length_var.get(), password_var),
            bg="#3498db", fg="white", font=("Helvetica", 14, "bold"),
            padx=20, pady=10, relief=tk.FLAT, cursor="hand2"
        ).pack(pady=20)

        tk.Button(
            content_frame,
            text="Copy to Clipboard",
            command=lambda: app.copy_to_clipboard(password_var.get()),
            bg="#2ecc71", fg="white", font=("Helvetica", 10),
            padx=10, pady=5, relief=tk.FLAT, cursor="hand2"
        ).pack(pady=5)

        footer_frame = tk.Frame(main_frame, bg="#2c3e50", height=60)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        footer_frame.pack_propagate(False)
        tk.Label(footer_frame, text="Password Management System", fg="white",
                 bg="#2c3e50", font=("Helvetica", 12)).pack(expand=True)

        tk.Button(footer_frame, text="Go Back", command=lambda: app.Return_to_Main(wn),
                  bg="#e74c3c", fg="white", font=("Helvetica", 10), relief=tk.FLAT).place(relx=0.02, rely=0.5, anchor=tk.W)

        wn.mainloop()

    # ------------------------ Signup/Login/Records --------------------------
    @staticmethod
    def do_signup(master, name, pas, strength_label=None):
        if not name or not pas:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        strength, _ = app.check_password_strength(pas)
        if strength == "Weak":
            if not messagebox.askyesno("Weak Password", "Your password is weak. Continue?"):
                return
        key, salt = app.generate_key(pas)
        with open(name + ".txt", "wb") as fdet:
            fdet.write(name.encode() + b"\n")
            fdet.write(key + b"\n")
            fdet.write(salt)
        with open(name + "-records.txt", "wb") as f:
            f.write(b"")
        messagebox.showinfo("Congratulations!!", "You have Successfully Signed Up!")
        master.destroy()

    @staticmethod
    def passMngr_signup():
        wn = tk.Tk()
        wn.geometry("600x550")
        wn.title("Sign Up")
        wn.configure(background="#f0f0f0")

        main_frame = tk.Frame(wn, bg="#f0f0f0", padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_frame = tk.Frame(main_frame, bg="#2c3e50", height=70)
        title_frame.pack(fill=tk.X, pady=(0, 30))
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="Create Your Account", fg="white", bg="#2c3e50",
                 font=("Helvetica", 18, "bold")).pack(expand=True)

        form_frame = tk.Frame(main_frame, bg="#f0f0f0")
        form_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(form_frame, text="Username:", bg="#f0f0f0", fg="#2c3e50", font=("Helvetica", 12)).pack(pady=(0, 5))
        e1 = tk.Entry(form_frame, font=("Helvetica", 12), relief=tk.FLAT, highlightcolor="#3498db", highlightthickness=1)
        e1.pack(pady=(0, 15), fill=tk.X, ipady=5)

        tk.Label(form_frame, text="Password:", bg="#f0f0f0", fg="#2c3e50", font=("Helvetica", 12)).pack(pady=(0, 5))
        e2 = tk.Entry(form_frame, show="*", font=("Helvetica", 12), relief=tk.FLAT, highlightcolor="#3498db", highlightthickness=1)
        e2.pack(pady=(0, 5), fill=tk.X, ipady=5)

        strength_var = tk.StringVar(value="Strength: Not evaluated")
        strength_label = tk.Label(form_frame, textvariable=strength_var, bg="#f0f0f0", fg="gray", font=("Helvetica", 10))
        strength_label.pack(pady=(0, 10))

        def update_strength(_=None):
            pw = e2.get()
            if pw:
                s, color = app.check_password_strength(pw)
                strength_var.set(f"Strength: {s}")
                strength_label.config(fg=color)
            else:
                strength_var.set("Strength: Not evaluated")
                strength_label.config(fg="gray")

        e2.bind("<KeyRelease>", update_strength)

        tk.Button(
            form_frame,
            text="Create Account",
            command=lambda: app.do_signup(wn, e1.get().strip(), e2.get().strip(), strength_label),
            bg="#2ecc71", fg="white", font=("Helvetica", 12, "bold"), padx=20, pady=10, relief=tk.FLAT, cursor="hand2"
        ).pack(pady=10)

        footer_frame = tk.Frame(main_frame, bg="#2c3e50", height=50)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        footer_frame.pack_propagate(False)
        tk.Label(footer_frame, text="Password Management System", fg="white", bg="#2c3e50", font=("Helvetica", 10)).pack(expand=True)

        wn.bind("<Return>", lambda _evt: app.do_signup(wn, e1.get().strip(), e2.get().strip(), strength_label))
        wn.mainloop()

    @staticmethod
    def do_newPass(wn, user, name, pas, strength_label=None):
        if not name or not pas:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        strength, _ = app.check_password_strength(pas)
        if strength == "Weak":
            if not messagebox.askyesno("Weak Password", "Your password is weak. Continue?"):
                return
        try:
            with open(user + ".txt", "rb") as f:
                lines = f.readlines()
                key = lines[1].strip()
        except Exception:
            messagebox.showerror("Error", "Could not retrieve encryption key")
            return
        encrypted_pas = app.encrypt_data(pas, key)
        with open(user + "-records.txt", "ab") as f:
            f.write(name.encode() + b"\n")
            f.write(encrypted_pas + b"\n\n")
        messagebox.showinfo("Success!", "New Record Added Successfully!")
        wn.destroy()

    @staticmethod
    def newPass(user):
        wn = tk.Tk()
        wn.geometry("600x500")
        wn.title("Add New Password")
        wn.configure(background="#f0f0f0")

        main_frame = tk.Frame(wn, bg="#f0f0f0", padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_frame = tk.Frame(main_frame, bg="#2c3e50", height=70)
        title_frame.pack(fill=tk.X, pady=(0, 30))
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="Add New Password", fg="white", bg="#2c3e50", font=("Helvetica", 18, "bold")).pack(expand=True)

        form_frame = tk.Frame(main_frame, bg="#f0f0f0")
        form_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(form_frame, text="Website/Service Name:", bg="#f0f0f0", fg="#2c3e50", font=("Helvetica", 12)).pack(pady=(0, 5))
        e1 = tk.Entry(form_frame, font=("Helvetica", 12), relief=tk.FLAT, highlightcolor="#3498db", highlightthickness=1)
        e1.pack(pady=(0, 15), fill=tk.X, ipady=5)

        tk.Label(form_frame, text="Password:", bg="#f0f0f0", fg="#2c3e50", font=("Helvetica", 12)).pack(pady=(0, 5))
        e2 = tk.Entry(form_frame, show="*", font=("Helvetica", 12), relief=tk.FLAT, highlightcolor="#3498db", highlightthickness=1)
        e2.pack(pady=(0, 5), fill=tk.X, ipady=5)

        strength_var = tk.StringVar(value="Strength: Not evaluated")
        strength_label = tk.Label(form_frame, textvariable=strength_var, bg="#f0f0f0", fg="gray", font=("Helvetica", 10))
        strength_label.pack(pady=(0, 10))

        tk.Button(
            form_frame,
            text="Generate Strong Password",
            command=lambda: app.fill_generated_password(e2, strength_var, strength_label),
            bg="#3498db", fg="white", font=("Helvetica", 10), padx=10, pady=5, relief=tk.FLAT, cursor="hand2"
        ).pack(pady=(0, 10))

        def update_strength(_=None):
            pw = e2.get()
            if pw:
                s, color = app.check_password_strength(pw)
                strength_var.set(f"Strength: {s}")
                strength_label.config(fg=color)
            else:
                strength_var.set("Strength: Not evaluated")
                strength_label.config(fg="gray")

        e2.bind("<KeyRelease>", update_strength)

        tk.Button(
            form_frame,
            text="Save Password",
            command=lambda: app.do_newPass(wn, user, e1.get().strip(), e2.get().strip(), strength_label),
            bg="#2ecc71", fg="white", font=("Helvetica", 12, "bold"), padx=20, pady=10, relief=tk.FLAT, cursor="hand2"
        ).pack(pady=10)

        footer_frame = tk.Frame(main_frame, bg="#2c3e50", height=50)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        footer_frame.pack_propagate(False)
        tk.Label(footer_frame, text="Password Management System", fg="white", bg="#2c3e50", font=("Helvetica", 10)).pack(expand=True)

        wn.bind("<Return>", lambda _evt: app.do_newPass(wn, user, e1.get().strip(), e2.get().strip(), strength_label))
        wn.mainloop()

    @staticmethod
    def fill_generated_password(entry_widget: tk.Entry, strength_var: tk.StringVar, strength_label: tk.Label):
        password = app.generatePas()
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, password)
        strength_var.set("Strength: Strong")
        strength_label.config(fg="green")

    @staticmethod
    def _load_records(user: str, key: bytes):
        records = []
        try:
            with open(user + "-records.txt", "rb") as f:
                content = f.read()
            entries = content.split(b"\n\n")
            for entry in entries:
                if not entry.strip():
                    continue
                parts = entry.split(b"\n")
                if len(parts) >= 2:
                    website = parts[0].decode("utf-8", errors="ignore")
                    encrypted_password = parts[1].strip()
                    if encrypted_password:
                        try:
                            password = app.decrypt_data(encrypted_password, key)
                        except Exception as e:
                            password = f"Decryption Error: {e}"
                        records.append((website, password))
        except FileNotFoundError:
            records = []
        return records

    @staticmethod
    def showRecords(user):
        # get user's key
        try:
            with open(user + ".txt", "rb") as f:
                lines = f.readlines()
                key = lines[1].strip()
        except Exception as e:
            messagebox.showerror("Error", f"Could not load records: {e}")
            return

        all_records = app._load_records(user, key)

        wn = tk.Tk()
        wn.geometry("900x600")
        wn.title("Your Saved Passwords")
        wn.configure(background="#f0f0f0")

        main_frame = tk.Frame(wn, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_frame = tk.Frame(main_frame, bg="#2c3e50", height=70)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="Your Saved Passwords", fg="white", bg="#2c3e50", font=("Helvetica", 18, "bold")).pack(expand=True)

        # search
        search_frame = tk.Frame(main_frame, bg="#f0f0f0")
        search_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(search_frame, text="Search:", bg="#f0f0f0").pack(side=tk.LEFT, padx=(0, 5))
        search_var = tk.StringVar()
        tk.Entry(search_frame, textvariable=search_var, font=("Helvetica", 10)).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        tk.Button(search_frame, text="Clear", command=lambda: search_var.set(""), bg="#e74c3c", fg="white", font=("Helvetica", 8)).pack(side=tk.LEFT)

        # tree
        columns = ("Website/Service", "Password")
        tree = ttk.Treeview(main_frame, columns=columns, show="headings", height=15)
        tree.heading("Website/Service", text="Website/Service")
        tree.heading("Password", text="Password (double-click to toggle)")
        tree.column("Website/Service", width=320, anchor=tk.W)
        tree.column("Password", width=320, anchor=tk.W)
        vsb = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # state: store real passwords in a dict keyed by iid
        real_passwords = {}

        def rebuild_table():
            tree.delete(*tree.get_children())
            term = search_var.get().lower().strip()
            for site, pwd in all_records:
                if term and term not in site.lower():
                    continue
                iid = tree.insert("", tk.END, values=(site, "•" * 12))
                real_passwords[iid] = pwd

        rebuild_table()

        def on_search(_=None):
            rebuild_table()

        search_var.trace_add("write", lambda *_: on_search())

        def on_double_click(event):
            sel = tree.selection()
            if not sel:
                return
            iid = sel[0]
            site, shown = tree.item(iid, "values")
            real = real_passwords.get(iid, "")
            if shown == "•" * 12:
                tree.item(iid, values=(site, real))
            else:
                tree.item(iid, values=(site, "•" * 12))

        tree.bind("<Double-1>", on_double_click)

        def copy_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Copy", "Select a row first")
                return
            iid = sel[0]
            pwd = real_passwords.get(iid, "")
            app.copy_to_clipboard(pwd)

        tk.Button(main_frame, text="Copy Selected Password", command=copy_selected,
                  bg="#3498db", fg="white", font=("Helvetica", 10), relief=tk.FLAT).pack(pady=8)

        footer_frame = tk.Frame(main_frame, bg="#2c3e50", height=50)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        footer_frame.pack_propagate(False)
        tk.Label(footer_frame, text="Password Management System", fg="white", bg="#2c3e50", font=("Helvetica", 10)).pack(expand=True)

        tk.Button(footer_frame, text="Close", command=wn.destroy, bg="#e74c3c", fg="white", font=("Helvetica", 10), relief=tk.FLAT).place(relx=0.02, rely=0.5, anchor=tk.W)

        wn.mainloop()

    @staticmethod
    def login_home(root, user):
        root.destroy()
        wn = tk.Tk()
        wn.geometry("800x600")
        wn.title("Password Manager - Dashboard")
        wn.configure(background="#f0f0f0")

        main_frame = tk.Frame(wn, bg="#f0f0f0", padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(main_frame, bg="#2c3e50", height=80)
        header_frame.pack(fill=tk.X, pady=(0, 30))
        header_frame.pack_propagate(False)
        tk.Label(header_frame, text=f"Welcome, {user}!", fg="white", bg="#2c3e50", font=("Helvetica", 20, "bold")).pack(expand=True)

        content_frame = tk.Frame(main_frame, bg="#f0f0f0")
        content_frame.pack(fill=tk.BOTH, expand=True)

        btn_style = {
            "bg": "#3498db",
            "fg": "white",
            "font": ("Helvetica", 14, "bold"),
            "width": 20,
            "height": 2,
            "relief": tk.FLAT,
            "cursor": "hand2",
        }

        tk.Button(content_frame, text="Save New Password", command=lambda: app.newPass(user), **btn_style).pack(pady=15)
        tk.Button(content_frame, text="Show Saved Passwords", command=lambda: app.showRecords(user), **btn_style).pack(pady=15)
        tk.Button(content_frame, text="Export Passwords", command=lambda: app.export_passwords(user), **btn_style).pack(pady=15)

        footer_frame = tk.Frame(main_frame, bg="#2c3e50", height=60)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        footer_frame.pack_propagate(False)
        tk.Label(footer_frame, text="Password Management System", fg="white", bg="#2c3e50", font=("Helvetica", 12)).pack(expand=True)

        tk.Button(footer_frame, text="Logout", command=lambda: app.Return(wn), bg="#e74c3c", fg="white", font=("Helvetica", 10), relief=tk.FLAT).place(relx=0.02, rely=0.5, anchor=tk.W)

        wn.mainloop()

    @staticmethod
    def export_passwords(user):
        try:
            with open(user + ".txt", "rb") as f:
                key = f.readlines()[1].strip()
            records = app._load_records(user, key)
            out_path = user + "-export.csv"
            with open(out_path, "w", encoding="utf-8", newline="") as f:
                f.write("Website/Service,Password\n")
                for site, pwd in records:
                    # naive CSV escaping for commas/quotes
                    site_ = '"' + site.replace('"', '""') + '"' if ("," in site or '"' in site) else site
                    pwd_ = '"' + pwd.replace('"', '""') + '"' if ("," in pwd or '"' in pwd) else pwd
                    f.write(f"{site_},{pwd_}\n")
            messagebox.showinfo("Export Successful", f"Passwords exported to {out_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export passwords: {e}")

    @staticmethod
    def check_login(name, pas):
        try:
            with open(name + ".txt", "rb") as f:
                lines = f.readlines()
                salt = lines[2].strip()
                key, _ = app.generate_key(pas, salt)
                if key == lines[1].strip():
                    return 1
                else:
                    messagebox.showerror("Error", "Invalid Login Credentials")
                    return 0
        except FileNotFoundError:
            messagebox.showerror("Error", "Invalid Login Credentials")
            return 0
        except Exception as e:
            messagebox.showerror("Error", f"Login error: {e}")
            return 0

    @staticmethod
    def do_login(root, master, name, pas):
        if not name or not pas:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        master.destroy()
        if app.check_login(name, pas) == 1:
            app.login_home(root, name)

    @staticmethod
    def passMngr_login(root):
        wn = tk.Tk()
        wn.geometry("600x500")
        wn.title("Login")
        wn.configure(background="#f0f0f0")

        main_frame = tk.Frame(wn, bg="#f0f0f0", padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_frame = tk.Frame(main_frame, bg="#2c3e50", height=70)
        title_frame.pack(fill=tk.X, pady=(0, 30))
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="Login to Your Account", fg="white", bg="#2c3e50", font=("Helvetica", 18, "bold")).pack(expand=True)

        form_frame = tk.Frame(main_frame, bg="#f0f0f0")
        form_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(form_frame, text="Username:", bg="#f0f0f0", fg="#2c3e50", font=("Helvetica", 12)).pack(pady=(0, 5))
        e1 = tk.Entry(form_frame, font=("Helvetica", 12), relief=tk.FLAT, highlightcolor="#3498db", highlightthickness=1)
        e1.pack(pady=(0, 15), fill=tk.X, ipady=5)

        tk.Label(form_frame, text="Password:", bg="#f0f0f0", fg="#2c3e50", font=("Helvetica", 12)).pack(pady=(0, 5))
        e2 = tk.Entry(form_frame, show="*", font=("Helvetica", 12), relief=tk.FLAT, highlightcolor="#3498db", highlightthickness=1)
        e2.pack(pady=(0, 20), fill=tk.X, ipady=5)

        tk.Button(
            form_frame,
            text="Login",
            command=lambda: app.do_login(root, wn, e1.get().strip(), e2.get().strip()),
            bg="#3498db", fg="white", font=("Helvetica", 12, "bold"), padx=20, pady=10, relief=tk.FLAT, cursor="hand2"
        ).pack(pady=10)

        footer_frame = tk.Frame(main_frame, bg="#2c3e50", height=50)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        footer_frame.pack_propagate(False)
        tk.Label(footer_frame, text="Password Management System", fg="white", bg="#2c3e50", font=("Helvetica", 10)).pack(expand=True)

        wn.bind("<Return>", lambda _evt: app.do_login(root, wn, e1.get().strip(), e2.get().strip()))
        wn.mainloop()

    # ------------------------ App shells (Main & Manager) --------------------
    @staticmethod
    def _open_pdf_cross_platform(path: str):
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                os.system(f"open '{path}'")
            else:
                os.system(f"xdg-open '{path}'")
        except Exception as e:
            messagebox.showerror("Open File", f"Could not open {path}: {e}")

    @staticmethod
    def passMngr(master):
        master.destroy()
        wn = tk.Tk()
        wn.geometry("800x600")
        wn.title("Password Manager")
        wn.configure(background="#f0f0f0")

        main_frame = tk.Frame(wn, bg="#f0f0f0", padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_frame = tk.Frame(main_frame, bg="#2c3e50", height=80)
        title_frame.pack(fill=tk.X, pady=(0, 50))
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="Password Management System", fg="white", bg="#2c3e50", font=("Helvetica", 20, "bold")).pack(expand=True)

        button_frame = tk.Frame(main_frame, bg="#f0f0f0")
        button_frame.pack(fill=tk.BOTH, expand=True)

        btn_style = {
            "bg": "#3498db",
            "fg": "white",
            "font": ("Helvetica", 14, "bold"),
            "width": 15,
            "height": 2,
            "relief": tk.FLAT,
            "cursor": "hand2",
        }

        tk.Button(button_frame, text="Sign Up", command=app.passMngr_signup, **btn_style).pack(pady=20)
        tk.Button(button_frame, text="Login", command=lambda: app.passMngr(wn) or app.passMngr_login(wn), **btn_style).pack_forget()
        tk.Button(button_frame, text="Login", command=lambda: app.passMngr_login(wn), **btn_style).pack(pady=20)

        footer_frame = tk.Frame(main_frame, bg="#2c3e50", height=60)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        footer_frame.pack_propagate(False)
        tk.Label(footer_frame, text="Secure Password Management", fg="white", bg="#2c3e50", font=("Helvetica", 12)).pack(expand=True)

        tk.Button(footer_frame, text="Return to Main", command=lambda: app.Return_to_Main(wn), bg="#e74c3c", fg="white", font=("Helvetica", 10), relief=tk.FLAT).place(relx=0.02, rely=0.5, anchor=tk.W)

        wn.mainloop()

    @staticmethod
    def Main():
        rootwn = tk.Tk()
        rootwn.geometry("900x600")
        rootwn.title("Password System")
        rootwn.configure(background="#f0f0f0")

        main_frame = tk.Frame(rootwn, bg="#f0f0f0", padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(main_frame, bg="#2c3e50", height=100)
        header_frame.pack(fill=tk.X, pady=(0, 50))
        header_frame.pack_propagate(False)
        tk.Label(header_frame, text="Password Management System", fg="white", bg="#2c3e50", font=("Helvetica", 24, "bold")).pack(expand=True)

        content_frame = tk.Frame(main_frame, bg="#f0f0f0")
        content_frame.pack(fill=tk.BOTH, expand=True)

        btn_style = {
            "bg": "#3498db",
            "fg": "white",
            "font": ("Helvetica", 14, "bold"),
            "width": 25,
            "height": 2,
            "relief": tk.FLAT,
            "cursor": "hand2",
        }

        tk.Button(content_frame, text="Password Guide", command=lambda: app._open_pdf_cross_platform("report.pdf"), **btn_style).pack(pady=15)
        tk.Button(content_frame, text="Password Generator", command=lambda: app.passGen(rootwn), **btn_style).pack(pady=15)
        tk.Button(content_frame, text="Password Manager", command=lambda: app.passMngr(rootwn), **btn_style).pack(pady=15)

        footer_frame = tk.Frame(main_frame, bg="#2c3e50", height=60)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        footer_frame.pack_propagate(False)
        tk.Label(footer_frame, text="Secure Your Digital Life", fg="white", bg="#2c3e50", font=("Helvetica", 12)).pack(expand=True)

        rootwn.mainloop()


# ---- Dependencies check (kept from your code) ---------------------------------
try:
    import cryptography  # noqa: F401
    import pyperclip  # noqa: F401
except ImportError:
    print("Please install required packages: pip install cryptography pyperclip")
    sys.exit(1)


if __name__ == "__main__":
    app.Main()
