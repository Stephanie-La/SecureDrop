import socket 
import time
import logging

HEADERSIZE = 20

logger = logging.getLogger(__name__)

def is_socket_connected(sock: socket.socket):
  try:
    # Read bytes without blocking or removing them, only peek
    data = sock.recv(16, socket.MSG_DONTWAIT | socket.MSG_PEEK)
    if len(data) == 0:
      return True
  except BlockingIOError:
    # socket is open and reading from it would block
    return False
  except ConnectionResetError:
    return True # socket was closed 
  except Exception as e:
    logger.exception("Unexpected exception when checking if a socket is closed.")
    return False
  return False

def register_self():
  email = input("Please register your email address on the server: ")
  create_client_list(email)

def create_client_list(some_data):
  clients_list = []

  clients_list.append(some_data)
  with open("clients_list.txt", "a") as file_c:
    file_c.write(clients_list)

def read_client_list():
  with open("clients_list.txt", "r") as file_c:
    clients_list = file_c.read()
    for client in clients_list:
      print(client)

#AF_INET = IPV4 , SOCK_STREAM = TCP
# streaming socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# bind to tuple: IP & port
s.bind((socket.gethostname(), 1235))
# queue of 5 connections to listen to at a time
s.listen(5)

# Listen forever for connections
while True:
  # if we get a connection, connect
  clientsocket, address = s.accept()
  # address - where are they coming from?
  # clientsocket - another socket object
  print(f"Connection from {address} has been established!")
  msg = "Greetings Gamer!"
  msg = f'{len(msg):<{HEADERSIZE}}' + msg
  # send info to clientsocket
  # send bytes
  clientsocket.send(bytes(msg, "utf-8"))

  # while True:
  #   time.sleep(3)
  #   msg = f"The time is! {time.time()}"
  #   msg = f'{len(msg):<{HEADERSIZE}}' + msg
  #   clientsocket.send(bytes(msg, "utf-8"))
