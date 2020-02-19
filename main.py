# Michael Long
# CS485
# Project #1: Implementing "PSU-CRYPT"
# Main

import psu_crypt
from sys import argv
from binascii import hexlify
from binascii import b2a_hex

def main(argv):

    # Verify that the base case works
    print("- - - - - - - - - Beginning base case - - - - - - - - -")
    test_key = 0xabcdef0123456789
    test_plain = 0x0123456789abcdef
    ret = psu_crypt._encrypt_block(test_plain, test_key)
    print(f'Cipher Text: {int.to_bytes(ret, 8, "big").hex()}')
    ret2 = psu_crypt._decrypt_block(ret, test_key)
    print(f'Plaintext Text: {int.to_bytes(ret2, 8, "big").hex()}')
    print("- - - - - - - - - Finishing base case - - - - - - - - -\n\n")


    # Work with the provided plaintext and secret text
    if (len(argv) != 3):
        # If no arguments provided, assume the text file fits the document specification of "plaintext.txt"
        plain_text_file = 'plaintext.txt'
        cipher_text_file = 'cyphertext.txt'
    else:
        plain_text_file = argv[1]
        cipher_text_file = argv[2]

    # Pad the plaintext
    try:
        f = open(plain_text_file, mode='r')
        plain_text = f.read()
        f.close()
    except:
        print("Error, could not find plaintext file or file has invalid characters used")

    # Encrypt the data
    cipher, pad_amt = psu_crypt.encrypt(plain_text, 0x1234567890abcdef)
    try:
        f = open(cipher_text_file, mode='w').close()
        f = open(cipher_text_file, mode='a')
        for i in range(len(cipher)):
            f.write(int.to_bytes(cipher[i], 8, "big").hex())
        #f.write(to_write)
        f.close()
    except:
        print("Error, could not find ciphertext file")


    # Decrypt it
    ret = psu_crypt.decrypt(cipher, 0x1234567890abcdef, pad_amt)
    print(ret)

    # Decrypt the written file
    try:
        f = open(cipher_text_file, mode='r')
        to_decrypt = f.read()
        f.close
    except:
        print("Error, could not find ciphertext file")

    lst_decrypt = []
    for i in range(len(to_decrypt)//8):
        temp = int(to_decrypt[i*8:(i+1)*8], 16)
        lst_decrypt.append(temp)
    print(lst_decrypt)
    ret = psu_crypt.decrypt(lst_decrypt, 0x1234567890abcdef, pad_amt)
    print(ret)
    pass

if __name__ == '__main__':
    main(argv)