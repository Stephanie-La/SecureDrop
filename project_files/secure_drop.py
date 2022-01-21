#!/user/bin/env python3
import os
import sys
import json
from pwinput import pwinput
import crypt
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
import socket


HEADERSIZE = 20

def encrypt(pt_file):
  # Retrieve the public key from user directory
  f = open("pub.pem", "r")
  pub_key = RSA.import_key(f.read())

  file_in = open(pt_file, "rb")
  
  session_key = get_random_bytes(16)

  # Encrypt session_key using public RSA key
  cipher_rsa = PKCS1_OAEP.new(pub_key)
  encrypt_sesh_key = cipher_rsa.encrypt(session_key)

  # Encrypt data w/ AES session key
  cipher_aes = AES.new(session_key, AES.MODE_EAX)
  ciphertext, tag = cipher_aes.encrypt_and_digest(file_in.read())
  file_in.close()
  file_out = open(pt_file, "wb")
  [ file_out.write(x) for x in (encrypt_sesh_key, cipher_aes.nonce,tag,ciphertext) ]
  file_out.close()

def decrypt(encrypted_file):
  f = open("priv.pem", "r")
  priv_key = RSA.import_key(f.read())

  file_in = open(encrypted_file, "rb")

  encrypt_sesh_key, nonce, tag, ciphertext = \
          [ file_in.read(x) for x in (priv_key.size_in_bytes(),16,16,-1) ]

  # Decrypt session key w/ private RSA key
  cipher_rsa = PKCS1_OAEP.new(priv_key)
  session_key = cipher_rsa.decrypt(encrypt_sesh_key)
  file_in.close()
  file_out = open(encrypted_file, "wb")

  # Decrypt the data w/ the AES session key
  cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
  file_out.write(cipher_aes.decrypt_and_verify(ciphertext,tag))
  file_out.close()

#Encryption for contact files, using Fernet keys
def jsencrypt(file_path):
  with open("key.key", 'rb') as _file_k:
    _key = _file_k.read()
  with open(file_path, 'rb') as _file_c:
    data = _file_c.read()

  fernet = Fernet(_key)
  _encrypted = fernet.encrypt(data)
  with open(file_path, "wb") as _file_c:
    _file_c.write(_encrypted)
  
#Decryption for contact files, using Fernet keys
def jsdecrypt(file_path):
  with open("key.key", 'rb') as _file_k:
    _key = _file_k.read()
  with open(file_path, 'rb') as _file_c:
    data = _file_c.read()
  fernet = Fernet(_key)
  _decrypted = fernet.decrypt(data)
  with open(file_path, "wb") as _file_c:
    _file_c.write(_decrypted)

# Writes email and password to file
def write_registry_file(registry_file,name,email,hash):
  # Write to file the user's name, email address, and the hashed PW
  file = open(registry_file, "w") 
  file.write(
    "%s\n%s\n%s\n"
    % (
      name,
      email,
      hash
    )
  )
  file.close()
  encrypt(registry_file)

#def find_email_in_file(contact_file, check_email, name):
  #if not is_empty(contact_file):
    #decrypt(contact_file)
    #file = open(contact_file, "r")
    #for line in file:
      #strip_line = line.rstrip()
      #if check_email == strip_line:
        #current_name = (file.next()).strip()
        #file.replace(current_name, name)
        
        #return True
        
    #encrypt(contact_file)
  #return False
  

# Write name and email into file
def write_contact_file(name, email):
  data = {
    "contact":{
      "name" : name,
      "email-address" : email
    }
  }
  if not is_empty("contacts_list.json"):
    with open("contacts_list.json", "a") as c_file:
      jsdecrypt("contacts_list.json")
      json.dump(data, c_file)
      c_file.truncate()
      jsencrypt("contacts_list.json")
  else:
    with open("contacts_list.json", "w") as c_file:
      json.dump(data, c_file)
      c_file.truncate()
      jsencrypt("contacts_list.json")

def open_server():
  #Utilize TCP to create a transport layer protocol to communicate w/ client's contact
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

def receive_ping():
  #AF_INET = IPV4 , SOCK_STREAM = TCP
  # streaming socket
  #s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

  # want to connect
  # 1234 is port #
  #s.connect((socket.gethostname(),1235))
  # client will be reomtoe to server, not on same machine
  # sockets can commuicate on the same machine through
  # local network or remote machines
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

def send_ping():
  #AF_INET = IPV4 , SOCK_STREAM = TCP
  # streaming socket
  s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  #Create a list
  _elist = []
  # Open file for reading
  with("contacts_list.json", "r") as _c_file:
    # Decrypt file
    jsdecrypt("contacts_list.json")
    # Store file in variable
    data = json.load(_c_file)
    # For contacts in the data's email
    for contacts in data['email-address']:
      # Append each email address to list
      # Hash emails from file
      contacts = crypt.crypt(contacts)
      _elist.append(contacts)
    #Encrypt the file again
    jsencrypt("contacts_list.json")
    # send server message to ask other users to send back their hashed email
    s.sendall('Please send your hashed email to confirm')
    # check the hash against the sent hash to determine if the desired email is online
    #if s.recv():
    # send a message to everyone verification
    # respond back with IP address
    # create pub/priv key with that person
    # call send ping function

    # try:
    #   # want to connect
    #   # 1234 is port #
    #   s.connect((socket.gethostname(),1235))
    # except:
    #   print("Failed to connect to server.")

  
  

def is_empty(file_path):
  # Checks if path exists and if the length of file is 0 (empty)
  return os.path.exists(file_path) and os.stat(file_path).st_size == 0

def registerUser(file_path):
  print("Enter Full Name: ")
  name = input()
  print("Enter Email Address: ")
  email = input()
  password = pwinput(prompt='Enter Password: ', mask = '*')
  reentered_password = pwinput(prompt='Re-enter Password: ', mask = '*')
  while password != reentered_password:
    print("Passwords do not match, please re-enter the password.\n")
    password =pwinput(prompt='Enter Password: ', mask = '*')
    reentered_password = pwinput(prompt='Re-enter Password: ', mask = '*')
  encrypted = crypt.crypt(password)
  write_registry_file(file_path, name, email, encrypted)
  print("\n" + "Passwords Match." + "\n" + "User Registered." + "\n" + "Exiting SecureDrop." + "\n")

def login(file_path):
  login_check = False
  login_counter = 0
  # An array for writing the stored user info into for comparison
  user_info = []
  decrypt(file_path)
  file = open(file_path, "r")
  # Places each line into each the array as a string
  for line in file:
    user_info.append(line.strip())
  
  # Compare the input email with the stored email

  #while login counter is less than 3, input attempts
  while login_check != True and login_counter <= 3:
    login_check = True
    print("Enter email address: ")
    email = input()
    password = pwinput(prompt = "Enter password: ", mask = '*')
  # Compare the hash of the input password with the stored hash, allows for comparison of passwords without use of the original password
    if user_info[1] != email.strip() or crypt.crypt(password, user_info[2]) != user_info[2]:
      print("Email and password combination invalid, Please try again.\n")
      login_counter +=1
      login_check = False
    
    if login_counter == 3:
      file.close()
      encrypt(file_path)
      print ("You have used up all of your attempts. Exiting Secure Drop.\n")
      sys.exit(0)
      
  file.close()
  encrypt(file_path)
  #open_client()
  #open_server()
  print("Welcome to Secure Drop.\n")

def add_contact():
  name = input("Enter Full Name: ")
  email = input("Enter Email Address: ")
  write_contact_file(name, email)
  print("Contact added")

def list_contacts(file_path):
  print("The following contacts are online: ")
  if is_empty(file_path):
    print("no friends lol")
  
  # 1. The contact information has been added to this user's contacts.
  # 2. The contact has also added this user's information to their contacts.
  # 3. The contact is online on the user's local network.
  jsdecrypt(file_path)
  if(is_socket_connected):
    print("* ", file_path.readlines(), "<", file_path.readlines(), ">")


def main():
  # Check if file is empty, passing in the path
  if is_empty("user_register.txt"):
    print("No users registered, would you like to register a new use (y/n)")
    decision = input()
    if decision == 'y':
      registerUser("user_register.txt") 
      # Write this function to get user login info
    else:
      print("Cannot continue with no way to log in, exiting program.")
      sys.exit(0)
  else:
    login("user_register.txt")
    print("Type \"help\" for user commands.\n")
    while True:
      #print("secure_drop> ")
      command = input()
      if command == "help":
        print("\"add\" -> Add a new contact.\n")
        print("\"list\" -> List all online contacts.\n")
        print("\"send\" -> Transfer file to contact.\n")
        print("\"exit\" -> Exit SecureDrop.\n")
      elif command == "add":
        add_contact()
        print("Type \"help\" for user commands.\n")
      elif command == "list":
        list_contacts("contact_list.txt")
        print("Type \"help\" for user commands.\n")
      elif command == "send":
        print("Working on this.\n")
        print("Type \"help\" for user commands.\n")
      elif command == "exit":
        print("Exiting SecureDrop")
        break
          
if __name__ == '__main__':
  main()