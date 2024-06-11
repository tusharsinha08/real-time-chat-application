import socket
import threading
import tkinter as tk
from tkinter import messagebox

DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "#FFFFFF"
BLACK = "#000000"
GREEN = "#04AA6D"

FONT = ("Helvetica", 17)
SMALL_FONT = ("Helvetica", 13)




def update_message_list(message):
    message_list.insert(tk.END, message)
    message_list.see(tk.END)

def connect_to_server():
    global client, SERVER_IP, SERVER_PORT, USERNAME
    SERVER_IP = entry_ip.get()
    SERVER_PORT = int(entry_port.get())
    USERNAME = entry_username.get()
    if SERVER_IP and SERVER_PORT and USERNAME:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((SERVER_IP, SERVER_PORT))
            client.sendall(USERNAME.encode())
            threading.Thread(target=listen_for_messages).start()
            update_message_list("Connected to the server")
            entry_ip.config(state=tk.DISABLED)
            entry_port.config(state=tk.DISABLED)
            entry_username.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Unable to connect to server: {str(e)}")
    else:
        messagebox.showwarning("Warning", "All fields are required")

def listen_for_messages():
    while True:
        try:
            message = client.recv(2048).decode('utf-8')
            if message:
                if message == "DISCONNECT":
                    update_message_list("Server is shutting down...")
                    client.close()
                    break
                update_message_list(message)
            else:
                client.close()
                break
        except:
            break

def send_message():
    message = entry_message.get()
    if message:
        client.sendall(message.encode())
        entry_message.delete(0, tk.END)
    

def logout():
    client.sendall("DISCONNECT".encode())
    client.close()
    root.destroy()



# GUI Setup
root = tk.Tk()
root.geometry("600x600")
root.title("Messenger Client")
root.resizable(False, False)

frame = tk.Frame(root, bg=DARK_GREY)
frame.pack(expand=True, fill=tk.BOTH)

connection_frame = tk.Frame(frame, bg=MEDIUM_GREY)
connection_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

message_frame = tk.Frame(frame, bg=MEDIUM_GREY)
message_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=5)

chat_frame = tk.Frame(frame, bg=MEDIUM_GREY)
chat_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=10)



label_ip = tk.Label(connection_frame, text="IP Address:", bg=MEDIUM_GREY, fg=WHITE, font=SMALL_FONT)
label_ip.grid(row=0, column=0, padx=5, pady=5)

entry_ip = tk.Entry(connection_frame, font=SMALL_FONT)
entry_ip.grid(row=0, column=1, padx=5, pady=5)

label_port = tk.Label(connection_frame, text="Port:", bg=MEDIUM_GREY, fg=WHITE, font=SMALL_FONT)
label_port.grid(row=0, column=2, padx=5, pady=5)

entry_port = tk.Entry(connection_frame, font=SMALL_FONT)
entry_port.grid(row=0, column=3, padx=5, pady=5)

label_username = tk.Label(connection_frame, text="Username:", bg=MEDIUM_GREY, fg=WHITE, font=SMALL_FONT)
label_username.grid(row=1, column=0, padx=5, pady=5)

entry_username = tk.Entry(connection_frame, font=SMALL_FONT)
entry_username.grid(row=1, column=1, padx=5, pady=5)

message_list = tk.Listbox(chat_frame, bg=MEDIUM_GREY, fg=WHITE, font=SMALL_FONT, height=20, width=60)
message_list.pack(side=tk.LEFT, padx=10, pady=10)

scrollbar_messages = tk.Scrollbar(chat_frame, command=message_list.yview, bg=MEDIUM_GREY)
scrollbar_messages.pack(side=tk.RIGHT, fill=tk.Y)
message_list.config(yscrollcommand=scrollbar_messages.set)

entry_message = tk.Entry(message_frame, font=SMALL_FONT, bg=WHITE, fg=BLACK)
entry_message.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)

send_button = tk.Button(message_frame, text="Send", font=SMALL_FONT, bg=OCEAN_BLUE, command=send_message)
send_button.pack(side=tk.LEFT, padx=10, pady=10)

connect_button = tk.Button(connection_frame, text="Connect", font=SMALL_FONT, bg=GREEN, command=connect_to_server)
connect_button.grid(row=1, column=2, padx=5, pady=5)

logout_button = tk.Button(connection_frame, text="Logout", font=SMALL_FONT, bg="red", command=logout)
logout_button.grid(row=1, column=3, padx=5, pady=5)


if __name__ == '__main__':
    root.mainloop()
