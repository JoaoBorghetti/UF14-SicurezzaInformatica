#TASK
#Symmetric encryption/decryption
#   Input: Choice -> Encrypt or Decrypt
#   Input: File path (relative or absolute) to encrypt/decrypt
#   Input: Destination file path of the result
#   Input: Choice -> with Authentication or without Authentication
#   Input: File name of the key
#Program loops until user aborts

import os
from unittest import result
from Crypto.Random import get_random_bytes
from Crypto.Cipher import Salsa20,AES

class SymScripError(Exception):
    '''Error executing Encryptor/Decryptor script'''

def encrypt(inputfile, outputfile,auth):
    data = read_file(inputfile,'r')
    if(auth == False):
        result,key = encryptNoAuth(data)
        #save encrypted file as binary
        write_file(result,outputfile,'wb')
        #ask for key file name
        keyname = input('Insert key file name (leave empty for default "key" name)\n>')
        if(len(keyname)< 1):
            #set default keyfile name
            keyname = 'key'
        #save key file as binary
        write_file(key,keyname,'wb')
    else:
        cipher,tag,nonce,key = encryptWithAuth(data)
        #concat all bytes
        result = nonce+tag+cipher
        #save encrypted file as binary
        write_file(result,outputfile,'wb')
        #ask for key file name
        keyname = input('Insert key file name (leave empty for default "key" name)\n>')
        if(len(keyname)< 1):
            #set default keyfile name
            keyname = 'key'
        #save key file as binary
        write_file(key,keyname,'wb')

def decrypt(inputfile, outputfile,auth):
    #get key file
    keyname = input('Insert key file name (leave empty for default "key" name)\n>')
    if(len(keyname)< 1):
    #set default keyfile name
        keyname = 'key'
    key = read_file(keyname,'rb')
    data = None
    if(auth == True):
        #AEX Encryption
        rawdata = read_file(inputfile,'rb')
        #rawdata -> nonce+tag+ciphertext
        #nonce length : 16 Bytes
        #tag length : 16 Bytes
        nonce = rawdata[:16]
        tag = rawdata[16:32]
        ciphertext = rawdata[32:]
        cipher = AES.new(key,AES.MODE_EAX,nonce)
        data = cipher.decrypt_and_verify(ciphertext,tag)
        if data == None:
            raise SymScripError('Unknown error during decryption')
        else:
            #write file as text
            write_file(data,outputfile,'wb')
    else:
        #Salsa20 Encryption
        rawdata = read_file(inputfile,'rb')
        #rawdata : nonce+ciphertext
        #nonce length : 8 Bytes
        nonce = rawdata[:8]
        ciphertext = rawdata[8:]
        cipher = Salsa20.new(key,nonce)
        data = cipher.decrypt(ciphertext)
        if data == None:
            raise SymScripError('Unknown error during decryption')
        else:
            #write file as text
            write_file(data,outputfile,'wb')

#SALSA20 Encryption
def encryptNoAuth(data:str):
    key = get_random_bytes(32)
    databytes = bytes(data.encode())
    cipher = Salsa20.new(key)
    encrypted= cipher.nonce + cipher.encrypt(databytes)
    return encrypted,key

#EAX Encryption
def encryptWithAuth(data:str):
    key = get_random_bytes(32)
    databytes = bytes(data.encode())
    cipher = AES.new(key,AES.MODE_EAX)
    encrypted, tag = cipher.encrypt_and_digest(databytes)
    return encrypted,tag,cipher.nonce,key

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