import socket 
from server import register_self

HEADERSIZE = 20

#AF_INET = IPV4 , SOCK_STREAM = TCP
# streaming socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# want to connect
# 1235 is port #
s.connect((socket.gethostname(),1235))
# client will be reomtoe to server, not on same machine
# sockets can commuicate on the same machine through
# local network or remote machines

register_self()


while True:
  full_msg = ''
  new_msg = True
  while True:
  # accept message, 1024 buffer size
    msg = s.recv(16)
    if new_msg:
      print(f'new message length: {msg[:HEADERSIZE]}')
      msglen = int(msg[:HEADERSIZE])
      new_msg = False
    full_msg += msg.decode("utf-8")

    if len(full_msg)-HEADERSIZE == msglen:
      print("full msg received")
      print(full_msg[HEADERSIZE:])
      new_msg = True
      full_msg = ''
  # decode bytes
  print(full_msg)