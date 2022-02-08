# TASK
# Hybrid Encrypt/Decrypt:
# Generate RSA Keys.
# Encrypt/decrypt file using an hybrid encryption schema or key encapsulation.
#
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from getpass import getpass

class ScriptError(Exception):
    '''Error occurred during execution'''
class ReadError(Exception):
    '''Error occurred during file read proccess'''
def read_file(path,mode:str,process=None):
    while True:
        try:
            with open(path,mode) as in_file:
                content = in_file.read()
            if process is None:
                return content
            return process(content)
        except (IOError,ReadError) as e:
            print('Cannot read/process file "'+path+'": '+ str(e))
        choice = input('(q to abort, anything else to try again)\n')
        if(choice == 'q'):
            raise ScriptError('Input aborted!')

def write_file(path,data,mode:str,process=None):
    while True:
        try:
            if process is None:
                processed = data
            else:
                processed = process(data)
            with open(path,mode) as out_file:
                return out_file.write(processed)
        except (IOError,ReadError) as e:
            print('Cannot write/process content to file "'+path+'": '+ str(e))
        choice = input('(q to abort, anything else to try again)\n')
        if(choice == 'q'):
            raise ScriptError('Input aborted!')

def check_and_process_data(data,typefile):
    if(typefile == 'input'):
        return 'a'
    elif(typefile == 'output'):
        return 'b'
    else:
        raise ScriptError('variable typefile "'+typefile+'" is not recognized (input,output)')

def genKeys():
    password = getpass('Type password to protect private key (leave empty for no password)\n')
    if(len(password) < 1):
        password = None
    keyname = input('Insert key pair name\n')
    key = RSA.generate(2048)
    publickey = key.public_key().export_key()
    privatekey = key.export_key(passphrase=password)
    write_file(keyname+'.pem',privatekey,'wb')
    write_file(keyname+'.pub',publickey,'wb')

def obtainCipherfromKey(key,password=None):
    rsa_key = RSA.importKey(extern_key=key,passphrase=password)
    return PKCS1_OAEP.new(rsa_key)

def Encrypt():
    data = read_file(input('Type file name to encrypt\n'),'rb')
    key = read_file(input('Type key name\n')+'.pub','rb')
    cipher = obtainCipherfromKey(key)
    encrypted = cipher.encrypt(data)
    outputfilename = input('Type encrypted file name:\n')
    write_file(outputfilename,encrypted,'wb')

def Decrypt():
    data = read_file(input('Type file name to encrypt\n'),'rb')
    key = read_file(input('Type key name\n')+'.pem','rb')
    password = getpass('Type password to protect private key (leave empty for no password)\n')
    if(len(password) < 1):
        password = None
    cipher = obtainCipherfromKey(key,password)
    decrypted = cipher.decrypt(data)
    outputfilename = input('Type decrypted file name:\n')
    write_file(outputfilename,decrypted,'wb')
    
if __name__ == '__main__':
    while True:
        initalPrompt = '''Select an option:
        1) Generate keys
        2) Encrypt file
        3) Decrypt file
        0) Exit
>'''
        try:
            choice = input(initalPrompt)
            if(choice == '1'):
                genKeys()
            elif(choice=='2'):
                Encrypt()
            elif(choice=='3'):
                Decrypt()
            elif(choice=='0'):
                quit()
        except ScriptError as hce:
            print(str(hce))