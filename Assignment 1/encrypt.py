
LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def main():
    # Read the blocks in, one per call (block==line by default)
    key = 'WXPETT'
    myMode = 'encrypt' # set to 'encrypt' or 'decrypt'
    if myMode == 'encrypt':
        fp = open("plaintext", "rb")
        myMessage = read_backwards(fp, PARA)
        translated = encryptMessage(key, myMessage).replace(" ", "")
        output = 'ciphertext'
    elif myMode == 'decrypt':
        fp = open("ciphertext", "rb")
        myMessage = read_backwards(fp, PARA)
        translated = decryptMessage(key, myMessage).replace(" ", "")
        output = 'plaintext'
    fop = open(output,'w')
    fop.write(translated)
    fop.close()
        
    
def encryptMessage(key, message):
    return translateMessage(key, message, 'encrypt')


def decryptMessage(key, message):
    return translateMessage(key, message, 'decrypt')


def translateMessage(key, message, mode):
    translated = [] # stores the encrypted/decrypted message string
    keyRound = 0
    keyIndex = 0
    key = key.upper()

    for symbol in message: # loop through each character in message
        num = LETTERS.find(symbol.upper())
        if num != -1: # -1 means symbol.upper() was not found in LETTERS
            if mode == 'encrypt':
                num += LETTERS.find(key[keyIndex]) + keyRound 
            elif mode == 'decrypt':
                num -= LETTERS.find(key[keyIndex]) + keyRound 

            num %= len(LETTERS) 

            
            if symbol.isupper():
                translated.append(LETTERS[num])
            elif symbol.islower():
                translated.append(LETTERS[num].lower())

            keyIndex += 1 
            if keyIndex == len(key):
                keyIndex = 0
                keyRound += 1
        else:
            
            translated.append(symbol)

    return ''.join(translated)


#---------- read_backwards.py----------#
# Read blocks of a file from end to beginning.
# Blocks may be defined by any delimiter, but the
#  constants LINE and PARA are useful ones.
# Works much like the file object method '.readline()':
#  repeated calls continue to get "next" part, and
#  function returns empty string once BOF is reached.

# Define constants
from os import linesep
LINE = linesep
PARA = linesep*2
READSIZE = 10000

# Global variables
buffer = ''

def read_backwards(fp, mode=LINE, sizehint=READSIZE, _init=[0]):
    """Read blocks of file backwards (return empty string when done)"""
    # Trick of mutable default argument to hold state between calls
    if not _init[0]:
        fp.seek(0,2)
        _init[0] = 1
    # Find a block (using global buffer)
    global buffer
    while 1:
        # first check for block in buffer
        delim = buffer.rfind(mode)
        if delim <> -1:     # block is in buffer, return it
            block = buffer[delim+len(mode):]
            buffer = buffer[:delim]
            return block+mode
        #-- BOF reached, return remainder (or empty string)
        elif fp.tell()==0:
            block = buffer
            buffer = ''
            return block
        else:           # Read some more data into the buffer
            readsize = min(fp.tell(),sizehint)
            fp.seek(-readsize,1)
            buffer = fp.read(readsize) + buffer
            fp.seek(-readsize,1)


# the main() function.
if __name__ == '__main__':
    main()