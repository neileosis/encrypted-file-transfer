'''
Client program

Written by Neil Hagstrom and Christopher Neave.
Created for CPSC 526 at the University of Calgary
'''
from __future__ import print_function
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import EasyCrypto
import argparse
import socket
import os
import binascii
import sys

#Returns a secure random IV for the session
def generateIV():
    return os.urandom(16)

#Initialize the socket, connecting to the server at the target host/ port
def initSocket(hostnamePort):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname, port = hostnamePort.split(":",1)
    soc.connect((hostname,int(port)))
    return soc

#Print to stderr and not to the output file
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def initparse():
    #Set up the required arguements with a parser
    parser = argparse.ArgumentParser(description = "Client for CPSC526 Assignment 3")
    parser.add_argument("command", type=str, choices=["write","read"],help="Determines if the client will be uploading or downloading to/from the server")
    parser.add_argument("filename", type=str, help="The name of the file to be used by the server application")
    parser.add_argument("hostnamePort", type = str, help="The target port for the client to connect to")
    parser.add_argument("cipher", type=str, choices=["aes256","aes128","none"], help="The cipher to be used for communicaiton with the server")
    parser.add_argument("key", nargs='?', help="The secret key to be used by the symmetric ciphers")
    args = parser.parse_args()
    return args

def main():
    #set up parser
    args = initparse()

    #Make sure all the required arguements are there and are valid
    iv = generateIV()
    if (args.key == None) and not(args.cipher == "none"):
        eprint("A key is required to connect to the server with AES128 and AES256")
        exit(-1)
    elif (args.key == None) and (args.cipher == "none"):
        #print("Connecting to the server without any encryption")
        cipher = None
    elif args.cipher == "none":
        eprint("No key is required when connecting with no cipher, exiting")
        exit(-1)
    #Set up the Ciphers if requested
    else:
        key = args.key
        while(len(key) < 32):
            key += key
        key = key[0:32]
        backend = default_backend()
        if(args.cipher == "aes128"):
            cipher = Cipher(algorithms.AES(key[0:16].encode("utf-8")),modes.CBC(iv),backend=backend) #Only want first half of the key

        else:
            cipher = Cipher(algorithms.AES(key.encode("utf-8")),modes.CBC(iv),backend=backend) #https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

    #Connect to the sever and send the inital command (cipher " " IV)
    soc = initSocket(args.hostnamePort)
    initialString = args.cipher + " " + binascii.hexlify(iv).decode("utf-8")
    soc.send(initialString.encode("utf-8"))

    #Check if you need to decrypt the message
    if(cipher != None):
        try:
            response = EasyCrypto.decryptAndUnpad(cipher,soc.recv(256)).decode("utf-8")	#recieve server response
        except ValueError:
            eprint (datetime.now(),"Key doesn't match. Closing connection.")
            soc.close()
            return False
        soc.send(EasyCrypto.encryptAndPad(cipher, key.encode("utf-8")))                #send key padded to server

    response = EasyCrypto.decryptAndUnpad(cipher, soc.recv(256)).decode("utf-8")
    if(response != "Cont"):
        eprint("There was an error: ", response)
        exit(-1)

    #Encrypt and send the command and filename to the server
    commandString = args.command + " " + args.filename
    soc.send(EasyCrypto.encryptAndPad(cipher, commandString.encode("utf-8")))

    #Check to see if the server is able to fulfil the command
    response = EasyCrypto.decryptAndUnpad(cipher, soc.recv(256)).decode("utf-8")

    #Run the command (recive and decypt the file or encrypt and send the file)
    if response == "Good" and args.command == "read":
        EasyCrypto.recieveFile(soc, cipher, args.filename)
    elif response == "Good" and args.command == "write":
        EasyCrypto.sendStdIn(soc, cipher, sys.stdin.buffer)
    else:
        eprint("There was an error:", response)
        soc.close()
        exit(-1)

main()
