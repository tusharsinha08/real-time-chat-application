import socket
import threading
import tkinter as tk
from tkinter import messagebox

HOST = '127.0.0.1'
PORT = 1234
LISTENER_LIMIT = 5
active_clients = []

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

def update_clients_list():
    clients_list.delete(0, tk.END)
    for username, _ in active_clients:
        clients_list.insert(tk.END, username)

def listen_for_messages(client, username):
    while True:
        try:
            message = client.recv(2048).decode('utf-8')
            if message:
                if message == "DISCONNECT":
                    remove_client(client, username)
                    break
                final_msg = username + ': ' + message
                send_message_to_all(final_msg)
                update_message_list(final_msg)
            else:
                remove_client(client, username)
                break
        except:
            remove_client(client, username)
            break

def send_message_to_client(client, message):
    try:
        client.sendall(message.encode())
    except:
        remove_client(client)

def send_message_to_all(message):
    for username, client in active_clients:
        send_message_to_client(client, message)

def client_handler(client):
    while True:
        try:
            username = client.recv(2048).decode('utf-8')
            if username:
                active_clients.append((username, client))
                update_clients_list()
                prompt_message = "SERVER: " + f"[{username}] joined the chat"
                send_message_to_all(prompt_message)
                update_message_list(prompt_message)
                break
            else:
                client.sendall("Username cannot be empty.".encode())
        except:
            return

    threading.Thread(target=listen_for_messages, args=(client, username)).start()

def remove_client(client, username=""):
    for user in active_clients:
        if user[1] == client:
            active_clients.remove(user)
            break
    client.close()
    if username:
        prompt_message = "SERVER: " + f"[{username}] left the chat"
        send_message_to_all(prompt_message)
        update_message_list(prompt_message)
        update_clients_list()

def start_server():
    global server, SERVER_RUNNING
    SERVER_RUNNING = True
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        server.listen(LISTENER_LIMIT)
        threading.Thread(target=accept_clients).start()
        update_message_list(f"Server started on {HOST}:{PORT}")
    except Exception as e:
        messagebox.showerror("Error", f"Unable to start server: {str(e)}")

def stop_server():
    global SERVER_RUNNING
    SERVER_RUNNING = False
    send_message_to_all("DISCONNECT")
    for client in active_clients:
        remove_client(client[1])
    server.close()
    update_message_list("Server stopped")

def accept_clients():
    while SERVER_RUNNING:
        try:
            client, address = server.accept()
            threading.Thread(target=client_handler, args=(client,)).start()
        except:
            break



# GUI Setup
root = tk.Tk()
root.geometry("800x600")
root.title("Messenger Server")
root.resizable(False, False)

frame = tk.Frame(root, bg=DARK_GREY)
frame.pack(expand=True, fill=tk.BOTH)

messages_frame = tk.Frame(frame, bg=MEDIUM_GREY)
messages_frame.grid(row=0, column=0, padx=10, pady=10, sticky=tk.NSEW)

clients_frame = tk.Frame(frame, bg=MEDIUM_GREY)
clients_frame.grid(row=0, column=1, padx=10, pady=10, sticky=tk.NSEW)

frame.grid_rowconfigure(0, weight=1)
frame.grid_columnconfigure(0, weight=3)
frame.grid_columnconfigure(1, weight=1)

message_list = tk.Listbox(messages_frame, bg=MEDIUM_GREY, fg=WHITE, font=SMALL_FONT, height=30, width=50)
message_list.pack(side=tk.LEFT, padx=10, pady=10)

scrollbar_messages = tk.Scrollbar(messages_frame, command=message_list.yview, bg=MEDIUM_GREY)
scrollbar_messages.pack(side=tk.RIGHT, fill=tk.Y)
message_list.config(yscrollcommand=scrollbar_messages.set)

clients_list = tk.Listbox(clients_frame, bg=MEDIUM_GREY, fg=WHITE, font=SMALL_FONT, height=30, width=20)
clients_list.pack(side=tk.LEFT, padx=10, pady=10)

scrollbar_clients = tk.Scrollbar(clients_frame, command=clients_list.yview, bg=MEDIUM_GREY)
scrollbar_clients.pack(side=tk.RIGHT, fill=tk.Y)
clients_list.config(yscrollcommand=scrollbar_clients.set)




start_button = tk.Button(frame, text="Start Server", font=SMALL_FONT, bg=GREEN, command=start_server)
start_button.grid(row=1, column=0, padx=10, pady=10, sticky=tk.EW)

stop_button = tk.Button(frame, text="Stop Server", font=SMALL_FONT, bg="red", command=stop_server)
stop_button.grid(row=1, column=1, padx=10, pady=10, sticky=tk.EW)

if __name__ == '__main__':
    SERVER_RUNNING = False
    root.mainloop()
