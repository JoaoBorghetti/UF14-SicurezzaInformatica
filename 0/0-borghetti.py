#Task
#"One time pad"-like encryption
#it sums the unicode codes of char at the same position between the key and the message to encrypt it

#Note
#utf-8 encoding is hard-coded to ensure the programs works with special characters
#could be extracted and given the choice to the user for which encoding would like to use

script_encoding = 'utf-8'

class OTPCipherError(Exception):
    '''Error executing one-time pad Cipher script'''

def encrypt(in_keyfile):
    #obtain pad string
    pad = read_file(in_keyfile,script_encoding) 
    messagepromt = '''write message: 
>'''
    #obtain message string
    plaintext = input(messagepromt)
    #length check
    if len(plaintext) > len(pad):
        raise OTPCipherError('Error: message lenght must be equal or less than the key length')
    encrypted_str = ''
    for char in plaintext:
        index = plaintext.find(char)
        #unicode code of message char
        plaintext_char_int = ord(char)
        #unicode code of pad char
        pad_char_int= ord(pad[index])
        char_sum = plaintext_char_int + pad_char_int
        #handle numbers outside allowed
        if(char_sum > 255):
            char_sum -= 255
        #append char rappresentation of unicode code
        encrypted_str += chr(char_sum)
    write_file(encrypted_str,'ciphertext',script_encoding)

def decrypt(in_cipherfile, in_keyfile):
    ciphertext = read_file(in_cipherfile,script_encoding)
    pad = read_file(in_keyfile,script_encoding)
    if len(ciphertext) > len(pad):
        raise OTPCipherError('Error: message lenght must be equal or less than the key length')
    decrypted_str = ''
    for char in ciphertext:
        index = ciphertext.find(char)
        ciphertext_char_int = ord(char)
        pad_char_int= ord(pad[index])
        char_diff = ciphertext_char_int - pad_char_int
        if(char_diff < 0):
            char_diff += 255
        decrypted_str += chr(char_diff)
    print('decrypted message contains : ' + decrypted_str)

def read_file(filename,in_encoding):
    try:
        #open file and read it with the desired encoding
        with open(filename,'r',encoding=in_encoding) as in_file:
            read_str = in_file.read()
    except IOError as e:
        raise OTPCipherError('Error: cannot read '+ filename+' file: '+ str(e))
    return read_str.strip('\n')

def write_file(content, filename, in_enconding):
    try:
        #open file and write it with the desired encoding
        with open(filename+'.txt','w', encoding=in_enconding) as out_file:
           out_file.write(content)
    except IOError as e:
        raise OTPCipherError('Error: cannot write '+filename+'.txt file: '+ str(e))
    print(filename+' file has been correctly saved with text "'+content+'" with '+script_encoding+ ' encoding!')

while True:
    prompt = '''Select an option:
    1) Encrypt (requires key.txt)
    2) Decrypt (requries key.txt and ciphertext.txt)
    0) Exit
>'''
    choice = input(prompt)
    try:
        if choice == '1':
            encrypt('key.txt')
        elif choice == '2':
            decrypt('ciphertext.txt','key.txt')
        elif choice == '0':
            break
    except OTPCipherError as e:
        print(e)