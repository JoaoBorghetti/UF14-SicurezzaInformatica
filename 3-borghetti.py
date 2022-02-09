# TASK
# Hybrid Encrypt/Decrypt:
# Generate RSA Keys.
# Encrypt/decrypt file using an hybrid encryption schema or key encapsulation.
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP,AES
from Crypto.Random import get_random_bytes
from getpass import getpass

class ScriptError(Exception):
    '''Error occurred during execution'''

class ReadError(Exception):
    '''Error occurred during file read proccess'''

def ask_and_read_file(prompt,mode:str,checkAndModify=None):
    while True:
        path = input(prompt)
        try:
            if checkAndModify is not None:
                path = checkAndModify(path)
            with open(path,mode) as in_file:
                content = in_file.read()
                return content
        except (IOError,ReadError) as e:
            print('Cannot read file "'+path+'": '+ str(e))
        choice = input('press "q" to abort (any to try again)\n')
        if(choice == 'q'):
            raise ScriptError('Input aborted!')

def ask_and_write_file(prompt,data,mode:str,CheckAndModify=None):
    while True:
        path = input(prompt)
        try:
            if CheckAndModify is not None:
                path = CheckAndModify(path)
            with open(path,mode) as out_file:
                return out_file.write(data)
        except (IOError,ReadError) as e:
            print('Cannot write/process content to file "'+path+'": '+ str(e))
        choice = input('(q to abort, anything else to try again)\n')
        if(choice == 'q'):
            raise ScriptError('Input aborted!')

def checkRSAKeyType(key:RSA.RsaKey,targetType:str):
    if(key.has_private and targetType == 'private'):
        return True
    elif((not key.has_private()) and targetType=='public'):
        return True
    else:
        raise False

def checkInput(path):
    if(os.path.isfile(path)):
        return path
    else:
        raise ReadError('File "'+path+'" does not exist!')

def checkOutput(path:str,defaultFilename:str='output_file'):
    if(os.path.isfile(path)):
        print('Overwritting "'+os.path.basename+'" file...')
        return path
    elif(os.path.isdir(path)):
        print('File will be set as "'+defaultFilename+'" in directory: "'+os.path.abspath(path)+'"')
        return os.path.abspath(path)+os.path.sep+defaultFilename
    elif(len(path) > 0):
        if(path.find(os.path.sep) > -1 or path.find(os.path.altsep)):
            #if path contains directory/ies
            dirpath,filename = os.path.split(path)
            if(len(dirpath) > 0):
                #if path is not "/[filename]"
                os.makedirs(dirpath,exist_ok=True)
            if(len(filename) >0):
                print('File will be set as "'+filename+'" in directory: "'+os.path.abspath(dirpath)+'"')
            else:
                 #if path is "[dirpath]/"
                print('File will be set as "'+defaultFilename+'" in directory: "'+os.path.abspath(dirpath)+'"')
                filename = defaultFilename
            return os.path.abspath(dirpath)+os.path.sep+filename
        print('File will be set as "'+path+'" in current directory: "'+os.getcwd()+'"')
        return path
    else:
        print('File will be set as "'+defaultFilename+'" in current directory:"'+os.getcwd()+'"')
        return defaultFilename

def generate_keys():
    password = getpass('Type password to protect private key (leave empty for no password)\n')
    if(len(password) < 1):
        password = None
    key = RSA.generate(2048)
    publickey = key.public_key().export_key()
    privatekey = key.export_key(passphrase=password)
    ask_and_write_file('Type private key file name:\n',privatekey,'wb',lambda x :checkOutput(x,defaultFilename='key_rsa')+'.pem')
    ask_and_write_file('Type public key file name:\n',publickey,'wb',lambda x :checkOutput(x,defaultFilename='key_rsa')+'.pub')

def Encrypt():
    data = ask_and_read_file('Type name of file to encrypt:\n','rb',checkInput)
    raw_public_key = ask_and_read_file('Type public key file:\n','rb',checkInput)
    #get RSA key object from public key
    rsa_public_key = RSA.import_key(raw_public_key)
    if(not checkRSAKeyType(rsa_public_key,'public')):
        #check if RSA key object is a public key object
        print('RSA key is not public')
        return
    session_key = get_random_bytes(16)
    #create cipher from session key
    data_cipher = AES.new(session_key,AES.MODE_EAX)
    #encrypt data with session_key-derived cipher
    encrypted_data,tag = data_cipher.encrypt_and_digest(data)
    #create cipher from public key
    session_key_cipher = PKCS1_OAEP.new(rsa_public_key)
    #encrypt session key with public_key cipher
    encrypted_session_key = session_key_cipher.encrypt(session_key)
    #save in file
    ask_and_write_file('Type encrypted output file name:\n',encrypted_session_key+(data_cipher.nonce+tag+encrypted_data),'wb',lambda data:checkOutput(data,defaultFilename='encrypted.bin'))

def Decrypt():
    data = ask_and_read_file('Type name of file to decrypt:\n','rb',checkInput)
    raw_private_key = ask_and_read_file('Type private key file:\n','rb',checkInput)
    password = getpass('Type password to protect private key (leave empty for no password)\n')
    if(len(password) < 1):
        #check if there is input
        password = None
    #get RSA key object from private key
    rsa_private_key = RSA.import_key(raw_private_key,passphrase=password)
    if(not checkRSAKeyType(rsa_private_key,'private')):
        #check if RSA key object is a private key object
        print('RSA key is not private')
        return
    #get session key section of the encrypted data
    encrypted_session_key = data[:rsa_private_key.size_in_bytes()]
    #get the actual data section of the encrypted data
    encrypted_data = data[rsa_private_key.size_in_bytes():]
    encrypted_data_nonce = encrypted_data[:16]
    encrypted_data_tag = encrypted_data[16:32]
    encrypted_data_text = encrypted_data[32:]
    #create cipher from private key
    session_key_cipher = PKCS1_OAEP.new(rsa_private_key)
    #decrypt session key with private_key-derived cipher
    session_key = session_key_cipher.decrypt(encrypted_session_key)
    #create cipher from session key
    data_cipher = AES.new(session_key,nonce=encrypted_data_nonce,mode=AES.MODE_EAX)
    #decrypt data with session_key-derived cipher
    decrypted_data = data_cipher.decrypt_and_verify(encrypted_data_text,encrypted_data_tag)
    #save in file
    ask_and_write_file('Type decrypted output file name:\n',decrypted_data,'wb',lambda x:checkOutput(x,defaultFilename='decrypted.bin'))

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
                generate_keys()
            elif(choice=='2'):
                Encrypt()
            elif(choice=='3'):
                Decrypt()
            elif(choice=='0'):
                quit()
        except ScriptError as hce:
            print(str(hce))