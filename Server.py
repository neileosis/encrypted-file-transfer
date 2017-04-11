'''
Client program

Written by Neil Hagstrom and Christopher Neave.
Created for CPSC 526 at the University of Calgary
'''
from datetime import datetime
from random import choice
from string import digits, ascii_lowercase, ascii_uppercase
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import EasyCrypto
import platform
import argparse
import socket
import os
import binascii

#the creation of the initial socket
def initSocket(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(),port))
    s.listen(1)
    return s


def dealWithClient(conn, addr, key):
    print(datetime.now(), " Client recived from IP: ", addr[0], " Port: ", addr[1])

    #recieve the initial message from the client including cipher and IV
    initialMessage = conn.recv(256).decode("utf-8")
    cipher, iv = initialMessage.split(" ",1)                #Split the initial message into cipher and IV
    ivbytes = binascii.unhexlify(iv)                        #Convert the IV back into bytes
    print("\t",datetime.now(), " Cipher: ", cipher, " IV:",iv)

    #check to see what encryption the client requested
    if(cipher == "aes256"):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key.encode("utf-8")),modes.CBC(ivbytes),backend=backend) #https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    elif(cipher == "aes128"):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key[0:16].encode("utf-8")),modes.CBC(ivbytes),backend=backend) #Only want first half of the key
    elif(cipher != "none"):
        print("\tThere was an error with the client selecting the cipher, closing")
        conn.send("There was an error selecting the cipher".encode("utf-8"))
        print("\t", datetime.now(), " done")
        conn.close()
        return False
    else:
        cipher = None

    #check for the proper key if they chose encryption
    if(cipher!=None):
	    #sends key to client to check if match and recieves key from client to match
        conn.send(EasyCrypto.encryptAndPad(cipher, key.encode("utf-8")))         #send key to client
        try:
            keycheck = EasyCrypto.decryptAndUnpad(cipher,conn.recv(256)).decode("utf-8")	#recieve client key
        except ValueError:
            print (datetime.now(),"Key doesn't match. Closing connection.")
            print("\t", datetime.now(), " done")
            conn.close()
            return False

    #Send the code to switch to the encryption and send the next command
    conn.send(EasyCrypto.encryptAndPad(cipher,"Cont".encode("utf-8")))

    commandMessage = EasyCrypto.decryptAndUnpad(cipher,conn.recv(256))

    command, fileName = commandMessage.decode("utf-8").split(" ",1)
    print("\t", datetime.now(), " Command: ", command, " Filename: ", fileName)

    #May want to send 'cont' before every function call to make sure client may see errors before sending
    if command == "read":
        if os.path.isfile(fileName):
            conn.send(EasyCrypto.encryptAndPad(cipher, "Good".encode("utf-8")))
            print("\t", datetime.now(), " Beginning to send file: ", fileName)
            EasyCrypto.sendFile(conn,cipher,fileName)
            print("\t", datetime.now(), " Finished sending file: ", fileName)
            print("\t", datetime.now(), " done")
            conn.close()
        else:
            #Send error that that is not a file they doesnt exist
            print("\tError: The file requested by the client doesn't exist or isn't a file")
            conn.send(EasyCrypto.encryptAndPad(cipher, "The file requested by the client doesn't exist or isn't a file".encode("utf-8")))
            print("\t", datetime.now(), " done")
            conn.close()
            return False
    else:
         #changed the access to work on both Windows and non-Windows machines, will error if it cannot write to that location
        if os.access("../", os.W_OK) and platform.system()!="Windows" or os.access("/", os.W_OK) and platform.system()=="Windows":    #Is the location writeable. Changed this to this path because with the filename if it didn't exist it would always be false
            conn.send(EasyCrypto.encryptAndPad(cipher, "Good".encode("utf-8")))
            print("\t", datetime.now(), " Beginning to recieve file: ", fileName)
            EasyCrypto.recieveFile(conn, cipher, fileName)
            print("\t", datetime.now(), " File tranfer is finished, connection closing")
            print("\t", datetime.now(), " done")
            conn.close()
        else:
            #Send error that the target file is not writeable
            print("Error: The server does not have permission to write to that location")
            conn.send(EasyCrypto.encryptAndPad(cipher, "The server does not have permission to write to that location".encode("utf-8")))
            print("\t", datetime.now(), " done")
            conn.close()
            return False

def main():
    #Parse all the arguements and make sure all required componenets are there
    parser = argparse.ArgumentParser(description = "Server for CPSC526 Assignment 3")
    parser.add_argument("port", type=int, help="The target port for the client to connect to")
    parser.add_argument("key", nargs='?', help="The secret key to be used by the symmetric ciphers")
    args = parser.parse_args()

    #if there is no key set up when the server runs, a random one will be created
    if args.key == None:                #Need to make key 256bits (32 bytes) in case AES256 is used
        key = ''.join(choice(ascii_lowercase+ascii_uppercase+digits) for i in range(32))
        print("Generated key: ", key)
    #if there is a key, repeat it until it is 32 bytes long
    else:
        key = args.key
        while(len(key) < 32):
            key += key
        key = key[0:32]
        print("Given key is: ", args.key, " Used key is: ", key)

    #create client socket
    s = initSocket(args.port)           #Set up the socket for listening on
    print(datetime.now(), " Listening on: ",s.getsockname())

    #accept and listen to client, when disconnected stay running and accept next connection
    while True:
    #Put in loop
        conn, addr = s.accept()                      #Accept the connection from the client
        dealWithClient(conn,addr,key)           #And see what they want



main()
