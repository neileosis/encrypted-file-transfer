from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import socket
import time
import sys

def encryptAndPad(cipher, data):
    padder = padding.PKCS7(128).padder()        #Pad the data as needed
    paddedData = padder.update(data) + padder.finalize()
    if cipher == None:
            return paddedData
    encryptor = cipher.encryptor()              #Encrypt the data and send
    ct = encryptor.update(paddedData) + encryptor.finalize()
    #print("\n\n\t Data: ", data)
    #print("\t paddedData: ", paddedData)
    #print("\t LPD: ",len(paddedData))
    #print("\t TPD: ", type(paddedData),'\n\n\n\n')
    #print("\t CT: ", ct)
    return ct

def decryptAndUnpad(cipher, ct):
    if cipher != None:
        decryptor = cipher.decryptor()
        ct = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    #print("\n\n\t CT: ", ct)
    #print("\t paddedData: ", paddedpt)
    #print("\t LPD: ",len(paddedpt))
    #print("\t TPD: ", type(paddedpt),'\n\n\n\n')
    pt = unpadder.update(ct) + unpadder.finalize()
    #print("\t PT: ", pt)
    return pt

def recieveFileTostdout(conn,cipher):
    out = sys.stdout
    while True:
        FlagAndChunkE = conn.recv(1024,socket.MSG_WAITALL)
        if FlagAndChunkE != b'':
                pt = decryptAndUnpad(cipher, FlagAndChunkE)
                out.buffer.write(pt[1:])
                out.flush()
                if pt[0:1] == b'T':
                    break
    return True

def recieveFile(conn, cipher, filename):
    file = open(filename,"wb")
    while True:
        FlagAndChunkE = conn.recv(1024,socket.MSG_WAITALL)
        if FlagAndChunkE != b'':
                pt = decryptAndUnpad(cipher, FlagAndChunkE)
                file.write(pt[1:])
                file.flush()
                if pt[0:1] == b'T':
                    break
    file.close()
    return True

def sendFile(conn, cipher, filename):
    file = open(filename,"rb")
    while True:
        chunk = file.read(1022)                         #One byte for the flag, and one for padding
        if len(chunk)==1022:                                #If its 1024 with no padding, it doesn't like it
            EOFAndChunk = b'F' + chunk
            conn.send(encryptAndPad(cipher,EOFAndChunk))
        else:
            EOFAndChunk = b'T' + chunk
            conn.send(encryptAndPad(cipher,EOFAndChunk))
            break
    file.close()
    return True

def sendStdIn(conn, cipher, data):
    while True:
        chunk = data.read(1022)                         #One byte for the flag, and one for padding
        if len(chunk)==1022:                                #If its 1024 with no padding, it doesn't like it
            EOFAndChunk = b'F' + chunk
            conn.send(encryptAndPad(cipher,EOFAndChunk))
        else:
            EOFAndChunk = b'T' + chunk
            conn.send(encryptAndPad(cipher,EOFAndChunk))
            break
    return True
