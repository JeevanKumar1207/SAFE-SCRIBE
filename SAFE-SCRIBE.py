import os
import random
import string
import webbrowser
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk 
import subprocess
import pyperclip  # For copying passwords to clipboard

ENC_FILE = "passwords.enc"
TEMP_FILE = "/tmp/passwords.tmp"

# Global variable to store encryption key
ENCRYPTION_KEY = None
root = None

class AutocompleteCombobox(ttk.Combobox):
    def set_completion_list(self, completion_list):
        self._completion_list = sorted(completion_list, key=str.lower)
        self._hits = []
        self._hit_index = 0
        self.position = 0
        self.bind('<KeyRelease>', self.handle_keyrelease)
        self.bind('<Down>', self.show_dropdown)

    def autocomplete(self, delta=0):
        if delta:
            self.delete(self.position, tk.END)
        else:
            self.position = len(self.get())
        _hits = []
        for element in self._completion_list:
            if element.lower().startswith(self.get().lower()):
                _hits.append(element)

        if _hits != self._hits:
            self._hit_index = 0
            self._hits = _hits

        if _hits:
            self.delete(0, tk.END)
            self.insert(0, _hits[self._hit_index])
            self.select_range(self.position, tk.END)

    def handle_keyrelease(self, event):
        if event.keysym in ("BackSpace", "Left", "Right", "Up", "Down"):
            return
        self.autocomplete()

    def show_dropdown(self, event=None):
        typed_value = self.get().strip()

        dropdown_values = [typed_value] if typed_value else []
        dropdown_values += [v for v in self._completion_list if v.lower() != typed_value.lower()]

        self['values'] = dropdown_values

        # Use 'postcommand' feature instead of self.event_generate to avoid recursion
        self.after_idle(lambda: self.event_generate('<Button-1>'))


def check_encryption_file():
    """Check if the encrypted file is exactly 32 bytes. If so, delete it and restart."""
    if os.path.exists(ENC_FILE) and os.path.getsize(ENC_FILE) == 32:
        os.remove(ENC_FILE)
        messagebox.showinfo("Reset", "Empty encryption file detected. Deleting...")
        return

def encrypt_db():
    """Encrypt the temporary file and store it in passwords.enc using the encryption key."""
    subprocess.run(f"openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:{ENCRYPTION_KEY} -in {TEMP_FILE} -out {ENC_FILE}", shell=True)
    os.remove(TEMP_FILE)  # Delete the temporary file after encryption

def decrypt_db():
    """Decrypt passwords.enc to the temporary file using the encryption key."""
    if os.path.exists(ENC_FILE):
        subprocess.run(f"openssl enc -aes-256-cbc -d -pbkdf2 -pass pass:{ENCRYPTION_KEY} -in \"{ENC_FILE}\" -out \"{TEMP_FILE}\"", shell=True)
        try:
            with open(TEMP_FILE, 'r', encoding='utf-8') as f:
                if not f.read().strip():
                    raise ValueError("Decryption failed! Check your encryption key.")
        except (FileNotFoundError, ValueError):
            messagebox.showerror("Error", "Decryption failed! Check your encryption key.")
            return False
    else:
        open(TEMP_FILE, 'w').close()
    return True

def load_services_and_usernames():
    """Store services and it's username"""
    services_set = set()
    service_usernames = {}
    if os.path.exists(TEMP_FILE):
        with open(TEMP_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) == 3:
                    service = parts[0].strip()
                    username = parts[1].strip()
                    services_set.add(service)
                    service_usernames.setdefault(service, []).append(username)
    return sorted(services_set), service_usernames

def generate_password(length=16):
    """Generate a random strong password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def add_password():
    """Add a new password to the database."""
    if not ENCRYPTION_KEY:
        messagebox.showerror("Error", "Encryption key not provided!")
        return

    if not decrypt_db():
        return

    def save_password():
        """Save the new password entry."""
        service = service_entry.get()
        username = username_entry.get()
        final_password = password_entry.get()

        if not service or not username or not final_password:
            messagebox.showerror("Error", "All fields must be filled!")
            return

        # Read the current data from TEMP_FILE, append the new password entry, and write back
        with open(TEMP_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{service} | {username} | {final_password}\n")

        encrypt_db()  # Encrypt and save the updated data
        messagebox.showinfo("Success", "Password saved!")

        add_window.destroy()

    def generate_new_password():
        """Generate a strong password and insert it into the password field."""
        password = generate_password()
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)

    def copy_to_clipboard():
        """Copy the password to clipboard."""
        pyperclip.copy(password_entry.get())

    def toggle_password_visibility():
        """Toggle password visibility when button is pressed."""
        if password_entry.cget('show') == '*':
            password_entry.config(show='')
        else:
            password_entry.config(show='*')

    # Create a new window for adding a password
    add_window = tk.Toplevel()
    add_window.title("Add Password")
    add_window.geometry("300x350")
    label_font = ("Arial", 10, "bold")

    sorted_services, service_usernames = load_services_and_usernames()

    # service entry
    tk.Label(add_window, text="Service Name:", font=label_font).pack(pady=2)
    service_entry = AutocompleteCombobox(add_window, value=sorted_services, width=40)
    service_entry.set_completion_list(sorted_services)
    service_entry.pack()
    service_entry.bind("<Return>", lambda e: username_entry.focus_set())

    # username entry
    tk.Label(add_window, text="Username:", font=label_font).pack(pady=2)
    username_entry = ttk.Combobox(add_window, width=40)
    username_entry.pack()

    def update_usernames(event=None):
        selected_service = service_entry.get().strip()
        usernames = service_usernames.get(selected_service, [])
        username_entry['values'] = usernames
        if usernames:
            username_entry.set("")

    service_entry.bind('<<ComboboxSelected>>', update_usernames)
    service_entry.bind('<FocusOut>', update_usernames)
    username_entry.bind("<Return>", lambda e: password_entry.focus_set())
    username_entry.bind("<Up>", lambda e: service_entry.focus_set())

    # password entry
    tk.Label(add_window, text="Password:", font=label_font).pack(pady=2)
    password_entry = tk.Entry(add_window, width =40, show="*")
    password_entry.pack()
    password_entry.bind("<Up>", lambda e: username_entry.focus_set())

    # Generate password button
    generate_button = tk.Button(add_window, text="Generate Password", command=generate_new_password)
    generate_button.pack(pady=5)

    # view password button
    view_button = tk.Button(add_window, text="View Password", command=toggle_password_visibility)
    view_button.pack(pady=5)

    # Copy password button
    copy_button = tk.Button(add_window, text="Copy Password", command=copy_to_clipboard)
    copy_button.pack(pady=5)

    # Save password when clicked
    save_button = tk.Button(add_window, text="Save Password", command=save_password)
    save_button.pack(pady=10)

    # Exit button
    exit_button = tk.Button(add_window, text="Exit", command=add_window.destroy)
    exit_button.pack(pady=5)

    # Keyboard Navigation Between Buttons
    button_list = [generate_button, view_button, copy_button, save_button, exit_button]

    def move_to_buttons(event=None):
        button_list[0].focus_set()

    def navigate_buttons(event):
        current = event.widget
        if current in button_list:
            idx = button_list.index(current)
            if event.keysym == 'Down':
                next_idx = (idx + 1) % len(button_list)
                button_list[next_idx].focus_set()
            elif event.keysym == 'Up':
                prev_idx = (idx - 1) % len(button_list)
                button_list[prev_idx].focus_set()
        if event.keysym == 'Return':
           current.invoke()

    password_entry.bind("<Return>", move_to_buttons)
    for btn in button_list:
        btn.bind("<Up>", navigate_buttons)
        btn.bind("<Down>", navigate_buttons)
        btn.bind("<Return>", navigate_buttons)

    service_entry.focus_set()

def retrieve_password():
    """Retrieve a password for a service."""
    if not decrypt_db():
        return

    sorted_services, service_usernames = load_services_and_usernames()

    retrieve_window = tk.Toplevel()
    retrieve_window.title("Retrieve Password")
    retrieve_window.geometry("400x350")
    label_font = ("Arial", 10, "bold")

    # service entry
    tk.Label(retrieve_window, text="Service Name:", font=label_font).pack(pady=2)
    service_entry = AutocompleteCombobox(retrieve_window, value=sorted_services, width=40)
    service_entry.set_completion_list(sorted_services)
    service_entry.pack()

    # username entry
    tk.Label(retrieve_window, text="Username:", font=label_font).pack(pady=2)
    username_entry = AutocompleteCombobox(retrieve_window, width=40)
    username_entry.pack()

    def update_usernames(event=None):
        selected_service = service_entry.get().strip()
        usernames = service_usernames.get(selected_service, [])
        username_entry.set_completion_list(usernames)
        username_entry['values'] = usernames
        if usernames:
            username_entry.set("")

    service_entry.bind("<Return>", lambda e: username_entry.focus_set())
    service_entry.bind('<<ComboboxSelected>>', update_usernames)
    service_entry.bind('<FocusOut>', update_usernames)
    username_entry.bind("<Up>", lambda e: service_entry.focus_set())

    def fetch_password():
        service = service_entry.get()
        username = username_entry.get()
        password = None

        with open(TEMP_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith(f"{service} | {username}"):
                    parts = line.strip().split('|')
                    if len(parts) == 3:
                        password = parts[2].strip()
                        break

        if password:
            retrieve_window = tk.Toplevel()
            retrieve_window.title(f"Password for {username} ({service})")

            tk.Label(retrieve_window, text=f"Service: {service}").pack()
            tk.Label(retrieve_window, text=f"Username: {username}").pack()
            password_label = tk.Label(retrieve_window, text="********")
            password_label.pack()

            def toggle_password_visibility_1():
                """Toggle password visibility."""
                if password_label.cget("text") == "********":
                    password_label.config(text=password)
                else:
                    password_label.config(text="********")

            def copy_password():
                """Copy password to clipboard."""
                pyperclip.copy(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!")

                retrieve_window.destroy()

            show_button = tk.Button(retrieve_window, text="Show Password", command=toggle_password_visibility_1)
            show_button.pack(pady=5)

            copy_button = tk.Button(retrieve_window, text="Copy Password", command=copy_password)
            copy_button.pack(pady=5)

            exit_button = tk.Button(retrieve_window, text="Exit", command=retrieve_window.destroy)
            exit_button.pack(pady=5)

        else:
            messagebox.showerror("Error", "Password not found!")

    fetch_button = tk.Button(retrieve_window, text="Fetch Password", command=fetch_password)
    fetch_button.pack(pady=5)
    exit_button = tk.Button(retrieve_window, text="Exit", command=retrieve_window.destroy)
    exit_button.pack(pady=5)

    button_list = [fetch_button, exit_button]

    def move_to_buttons(event=None):
        button_list[0].focus_set()

    def navigate_buttons(event):
        current = event.widget
        if current in button_list:
            idx = button_list.index(current)
            if event.keysym == 'Down':
                next_idx = (idx + 1) % len(button_list)
                button_list[next_idx].focus_set()
            elif event.keysym == 'Up':
                prev_idx = (idx - 1) % len(button_list)
                button_list[prev_idx].focus_set()
        if event.keysym == 'Return':
           current.invoke()

    username_entry.bind("<Return>", move_to_buttons)
    for btn in button_list:
        btn.bind("<Up>", navigate_buttons)
        btn.bind("<Down>", navigate_buttons)
        btn.bind("<Return>", navigate_buttons)

    service_entry.focus_set()

def edit_password():
    """Edit an existing stored password."""
    if not decrypt_db():
        return

    services = []
    with open(TEMP_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        services = {line.split('|')[0].strip() for line in f}

    if not services:
        messagebox.showerror("Error", "No services available!")
        return

    service_selection = simpledialog.askstring("Select Service", "Enter the number corresponding to the service:\n" +
                                               "\n".join(f"{idx + 1}. {service}" for idx, service in enumerate(services)))

    try:
        service_index = int(service_selection) - 1
        service = list(services)[service_index]
    except (ValueError, IndexError):
        messagebox.showerror("Error", "Invalid selection!")
        return

    usernames = []
    with open(TEMP_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.startswith(service):
                usernames.append(line.split('|')[1].strip())

    if not usernames:
        messagebox.showerror("Error", "No usernames found for this service!")
        return

    username_selection = simpledialog.askstring("Select Username", "Enter the number corresponding to the username:\n" +
                                                "\n".join(f"{idx + 1}. {username}" for idx, username in enumerate(usernames)))

    try:
        username_index = int(username_selection) - 1
        username = usernames[username_index]
    except (ValueError, IndexError):
        messagebox.showerror("Error", "Invalid selection!")
        return

    new_password = simpledialog.askstring("New Password", f"Enter a new password for {username} ({service}):", show="*")
    if new_password:
        lines = []
        with open(TEMP_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        with open(TEMP_FILE, 'w', encoding='utf-8') as f:
            for line in lines:
                if line.startswith(f"{service} | {username}"):
                    f.write(f"{service} | {username} | {new_password}\n")  # Replace the password
                else:
                    f.write(line)

        encrypt_db()  # Encrypt and save the updated data
        messagebox.showinfo("Success", "Password updated!")

def delete_service():
    if not decrypt_db():
        return

    services = []
    with open(TEMP_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            service = line.split('|')[0].strip()
            if service not in services:
                services.append(service)

    if not services:
        messagebox.showinfo("Info", "No services found!")
        return

    service_list = "\n".join([f"{i+1}. {s}" for i, s in enumerate(services)])
    service_choice = simpledialog.askinteger("Delete Service", f"Select a service to delete:\n{service_list}")

    if not service_choice or service_choice < 1 or service_choice > len(services):
        return

    service_to_delete = services[service_choice - 1]

    with open(TEMP_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    with open(TEMP_FILE, 'w', encoding='utf-8') as f:
        for line in lines:
            if not line.startswith(service_to_delete):
                f.write(line)

    encrypt_db()
    messagebox.showinfo("Success", "Service deleted!")

def delete_username():
    if not decrypt_db():
        return

    services = []
    with open(TEMP_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            service = line.split('|')[0].strip()
            if service not in services:
                services.append(service)

    if not services:
        messagebox.showinfo("Info", "No services found!")
        return

    service_list = "\n".join([f"{i+1}. {s}" for i, s in enumerate(services)])
    service_choice = simpledialog.askinteger("Select Service", f"Select a service:\n{service_list}")

    if not service_choice or service_choice < 1 or service_choice > len(services):
        return

    selected_service = services[service_choice - 1]

    usernames = []
    with open(TEMP_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith(selected_service):
                usernames.append(line.split('|')[1].strip())

    if not usernames:
        messagebox.showinfo("Info", "No usernames found for the selected service!")
        return

    username_list = "\n".join([f"{i+1}. {u}" for i, u in enumerate(usernames)])
    username_choice = simpledialog.askinteger("Delete Username", f"Select a username to delete:\n{username_list}")

    if not username_choice or username_choice < 1 or username_choice > len(usernames):
        return

    username_to_delete = usernames[username_choice - 1]

    with open(TEMP_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    with open(TEMP_FILE, 'w', encoding='utf-8') as f:
        for line in lines:
            if not line.startswith(f"{selected_service} | {username_to_delete}"):
                f.write(line)

    encrypt_db()
    messagebox.showinfo("Success", "Username deleted!")

def change_encryption_key():
    global ENCRYPTION_KEY
    if not decrypt_db():
        return

    new_key = simpledialog.askstring("Change Encryption Key", "Enter a new encryption key:", show='*')
    if not new_key:
        messagebox.showerror("Error", "Encryption key not changed!")
        return

    ENCRYPTION_KEY = new_key
    encrypt_db()
    messagebox.showinfo("Success", "Encryption key changed successfully!")
def open_linkedin(event=None):
    webbrowser.open("https://www.linkedin.com/in/jeevankumar12/") 
def open_github(event=None):
    webbrowser.open("https://github.com/jeevankumar1207")
def on_enter(event, text_widget):
    text_widget.tag_add("highlight", "1.4", "1.19")
    text_widget.tag_config("highlight", foreground="blue")
def on_leave(event, text_widget):
    text_widget.tag_remove("highlight", "1.4", "1.19")
def on_enter_github(event, github_widget):
    github_widget.tag_add("highlight", "1.8", "1.30")
    github_widget.tag_config("highlight", foreground="blue")
def on_leave_github(event, github_widget):
    github_widget.tag_remove("highlight", "1.8", "1.30")

def run_gui():
    """Run the GUI interface."""
    global ENCRYPTION_KEY

    check_encryption_file()

    # Ask for the encryption key if the file exists
    if os.path.exists(ENC_FILE):
        messagebox.showinfo("SAFE-SCRIBE","WELLCOME                          SAFE-SCIBE by:Jeevan Kumar S github: @jeevankumar1207")
        ENCRYPTION_KEY = simpledialog.askstring("SAFE-SCRIBE", "Enter the encryption key to access passwords:", show='*')

    if not os.path.exists(ENC_FILE):  # If the encrypted file does not exist
        # Ask the user for the encryption key to create the file
        ENCRYPTION_KEY = simpledialog.askstring("SAFE-SCRIBE", "Enter the encryption key to create passwords:", show='*')
        messagebox.showinfo("SAFE-SCRIBE","WELLCOME                          You can now add your passwords.                       SAFE-SCIBE by:Jeevan Kumar S")

    root = tk.Tk()
    root.title("SAFE-SCRIBE")
    root.geometry("250x500")

    # function Button in the right frame
    tk.Button(root, text="Add Password", font=("Arial", 10, "bold"), command=add_password, width=20, height=2).pack(pady=5)
    tk.Button(root, text="Retrieve Password", font=("Arial", 10, "bold"), command=retrieve_password, width=20, height=2).pack(pady=5)
    tk.Button(root, text="Edit Password", font=("Arial", 10, "bold"), command=edit_password, width=20, height=2).pack(pady=5)
    tk.Button(root, text="Delete Service", font=("Arial", 10, "bold"), command=delete_service, width=20, height=2).pack(pady=5)
    tk.Button(root, text="Delete Username", font=("Arial", 10, "bold"), command=delete_username, width=20, height=2).pack(pady=5)
    tk.Button(root, text="Change Encryption Key", font=("Arial", 10, "bold"), command=change_encryption_key, width=20, height=2).pack(pady=5)
    tk.Button(root, text="Exit", font=("Arial", 10, "bold"), command=root.quit, width=20, height=2).pack(pady=5)

    text_widget = tk.Text(root, height=1, width=30, font=("Arial", 12), wrap="word", bd=0)
    text_widget.insert("1.0", "by: Jeevan Kumar s")
    text_widget.config(state=tk.DISABLED)
    text_widget.pack(pady=10)
    text_widget.bind("<Enter>", lambda event: on_enter(event, text_widget))
    text_widget.bind("<Leave>", lambda event: on_leave(event, text_widget))
    text_widget.bind("<Button-1>", lambda e: open_linkedin())

    github_widget = tk.Text(root, height=1, width=30, font=("Arial", 12), wrap="word", bd=0)
    github_widget.insert("1.0", "github: @jeevankumar1207")
    github_widget.config(state=tk.DISABLED)
    github_widget.pack(pady=10)
    github_widget.bind("<Enter>", lambda event: on_enter_github(event, github_widget))
    github_widget.bind("<Leave>", lambda event: on_leave_github(event, github_widget))
    github_widget.bind("<Button-1>", lambda e: open_github())

    root.mainloop()

if __name__ == "__main__":
    run_gui()
