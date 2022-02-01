#TASK
#Symmetric encryption/decryption
#   Input: Choice -> Encrypt or Decrypt
#   Input: File path (relative or absolute) to encrypt/decrypt
#   Input: Destination file path of the result
#   Input: Choice -> with Authentication or without Authentication
#   Input: File name of the key
#Program loops until user aborts

import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import Salsa20,AES
from getpass import getpass
from Crypto.Protocol.KDF import scrypt

class SymScripError(Exception):
    '''Error executing Encryptor/Decryptor script'''

def encrypt(inputfile, outputfile,auth):
    data = read_file(inputfile,'r')
    password = getpass('Insert password:\n')
    salt = get_random_bytes(16)
    key = scrypt(password=password,salt=salt,key_len=32,N=2**20,r=8,p=1,num_keys=1)
    if(auth == False):
        crypted = encryptNoAuth(data,key)
        result = salt+crypted
        #save encrypted file as binary
        write_file(result,outputfile,'wb')
    else:
        cipher,tag,nonce = encryptWithAuth(data,key)
        #concat all bytes
        result = salt+nonce+tag+cipher
        #save encrypted file as binary
        write_file(result,outputfile,'wb')

def decrypt(inputfile, outputfile,auth):
    #get salt values
    rawdata = read_file(inputfile,'rb')
    password = getpass('Insert password:\n')
    salt = rawdata[:16]
    key = scrypt(password=password,salt=salt,key_len=32,N=2**20,r=8,p=1,num_keys=1)
    strippedData = rawdata[16:]
    if(auth == True):
        #AEX Encryption
        #strippedData -> nonce+tag+ciphertext
        #nonce length : 16 Bytes
        #tag length : 16 Bytes
        nonce = strippedData[:16]
        tag = strippedData[16:32]
        ciphertext = strippedData[32:]
        cipher = AES.new(key,AES.MODE_EAX,nonce)
        try:
            data = cipher.decrypt_and_verify(ciphertext,tag)
        except ValueError as ve:
            raise SymScripError('Error in decryption:'+str(ve))
        if data == None:
            raise SymScripError('Unknown error during decryption')
        else:
            #write file as text
            write_file(data,outputfile,'wb')
    else:
        #Salsa20 Encryption
        #rawdata : nonce+ciphertext
        #nonce length : 8 Bytes
        nonce = strippedData[:8]
        ciphertext = strippedData[8:]
        cipher = Salsa20.new(key,nonce)
        data = cipher.decrypt(ciphertext)
        if data == None:
            raise SymScripError('Unknown error during decryption')
        else:
            #write file as text
            write_file(data,outputfile,'wb')

#SALSA20 Encryption
def encryptNoAuth(data:str,key:bytes):
    databytes = bytes(data.encode())
    cipher = Salsa20.new(key)
    encrypted= cipher.nonce + cipher.encrypt(databytes)
    return encrypted

#EAX Encryption
def encryptWithAuth(data:str, key:bytes):
    databytes = bytes(data.encode())
    cipher = AES.new(key,AES.MODE_EAX)
    encrypted, tag = cipher.encrypt_and_digest(databytes)
    return encrypted,tag,cipher.nonce

def read_file(filepath,mode):
    #simple function for reading a file
    try:
        with open(filepath,mode) as in_file:
            read_str = in_file.read()
    except IOError as e:
        raise SymScripError('Error: cannot read '+ filepath+' file: '+ str(e))
    return read_str

def write_file(data,filename,mode):
    #simple function for writing a file
    try:
        with open(filename,mode) as out_file:
            out_file.write(data)
    except IOError as e:
        raise SymScripError('Error: cannot write on '+ filename+' file: '+ str(e))

def Validate(filepath,validator):
    #check path:  whether it exist, is a regular file or a directory and act accordingly
    resultCode,argument = validator(filepath)
    if(resultCode ==-1):
        raise SymScripError(argument)
    elif(resultCode==0):
        return argument
    else:
        raise SymScripError('Unknown Error during validation')


def checkInput(_path):
    #check if path is an actual path and return it again, otherwise send error code with its description
    if(os.path.isfile(_path)):
        return 0,_path
    else:
        return -1,'File "'+_path+'" does not exist'

def checkOutput(_path):
    if(os.path.isfile(_path)):
        #check if path is a file and warn of the overwrite
        print('file "'+os.path.basename(_path) +'" will be overwritten\n')
        return 0,_path
    if (os.path.isdir(_path)):
        #check if file is a directory and set a default file name and sent the absolute path of the destination file
        print('file will be saved as "OutputFile" in directory "'+os.path.abspath(_path)+'"\n')
        return 0,os.path.abspath(_path)+os.path.sep+'OutputFile'
    elif(len(_path)>0):
        #(if not a file or a directory) check if there is a filename to set and set it to write inside current directory
        print('file will be saved as "'+_path+'" in directory "'+os.getcwd()+'"\n')
        return 0, _path
    else:
        #path is empty, default file name will be written inside current directory
        print('file will be saved as "OutputFile" in directory "'+os.getcwd()+'"\n')
        return 0,'OutputFile'


if __name__ == "__main__":
    while True:
        prompt = '''Select an option:
        1) Encrypt
        2) Decrypt
        0) Exit
>'''
        choice = input(prompt)
        try:
            if choice == '1':
                inputFile = Validate(input('Insert plaintext file path\n>'),checkInput)
                outputFile = Validate(input('Insert encrypted destination file path (empty filename for default name "OutputFile")\n>'),checkOutput)
                authChoice = input('Include authentication? y/n (any to go back)\n>')
                if(authChoice.lower() == 'y'):
                    encrypt(inputFile,outputFile,True)
                elif(authChoice.lower() == 'n'):
                    encrypt(inputFile,outputFile,False)
            elif choice == '2':
                inputFile = Validate(input('insert encrypted file path\n>'),checkInput)
                outputFile = Validate(input('insert plain text destination file path\n>'),checkOutput)
                authChoice = input('Is the encrypted file authenticated? y/n (any to go back)\n>')
                if(authChoice == 'y'):
                    decrypt(inputFile,outputFile,True)
                else:
                    decrypt(inputFile,outputFile,False)
            elif choice == '0':
                break
        except SymScripError as e:
            print(e)