#TASK
#Certification-authenticated Encryption



from os.path import isfile
from Crypto.PublicKey import RSA

class CertError(Exception):
    '''Certification Error'''
class ReadProcessingError(Exception):
    '''Data Read Process Error'''
class GenericError(Exception):
    '''Execution Error '''

def read_file(name,AbortMessage,defaultValue='',dataProcess=lambda data:data):
    prompt = 'Insert File path to read '
    if defaultValue != '':
        prompt += '(Leave blank for default "'+defaultValue+'")'
    prompt+='\n'
    exitPrompt = 'press (q) to abort insertion (anything to try again)\n'
    while True:
        filepath = input(prompt)
        try:
            with open(filepath,'rb') as file:
                content = file.read()
            return dataProcess(content)
        except (IOError, ReadProcessingError) as e:
            print('Error while reading "'+name+' file":\n'+ str(e))
        exitchoice = input(exitPrompt)
        if exitchoice.lower() == 'q':
            raise GenericError(AbortMessage)

def write_file(data,AbortMessage,defaultValue='',dataProcess=lambda data:data):
    prompt = 'Insert Name/pathname to write the file to'
    if defaultValue != '':
        prompt += '(leave blank for default "'+defaultValue+'")'
    prompt+='\n'
    exitPrompt = 'press (q) to abort insertion (anything to try again)\n'
    while True:
        filepath = input(prompt)
        if filepath == '':
            filepath = defaultValue
        try:
            if isfile(filepath):
                overwriteChoice = input('File "'+filepath+'"already exists, overwrite it? (n to cancel, anything else to continue)\n')
                if overwriteChoice.lower() == 'n':
                    continue
                with open(filepath,'wb') as file:
                    file.write(data)
                return filepath
        except (IOError, ReadProcessingError) as e:
            print('Error while writing "'+filepath+' file":\n'+ str(e))
        exitchoice = input(exitPrompt)
        if exitchoice.lower() == 'q':
            raise GenericError(AbortMessage)

def GenerateKeys():
    keypair = RSA.generate(2048)
    publickey = keypair.public_key().export_key()
    privatekey = keypair.export_key()
def GenerateCert():
    return ''
def Encrypt():
    return ''
def Decrypt():
    return ''


prompt= '''Select an option:
    1) Create Certificate
    2) Encrypt file
    3) Decrypt File
    0)
'''
