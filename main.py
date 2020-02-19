# Michael Long
# CS485
# Project #1: Implementing "PSU-CRYPT"
# Main

import psu_crypt
from sys import argv

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
    if (len(argv) != 7):
        # If no arguments provided, assume the text file fits the document specification of "plaintext.txt" and "cyphertext.txt"
        print("Error, invalid input, using default values\nCompile with python3 main.py <key>", 
        "<cypher key> <cypher pad amount> <plain text input> <cypher text input>",
        " <plain text output> <cipher text output>")

        print("<key>: secret value to use\n", 
        "<cypher key>: whatever key was used to encrypt '<cypher text input>'\n",
        "<cypher pad amount>: whatever amount of characters of padding was used\n",
        "<plain text input>: the text to test the encryption on\n",
        "<cypher text input>: the text to test the decryption with, assumes input of 16 hex values in the form '0x...'\n",
        "<plain text output>: where to write the result of decrypting '<cypher text input>'\n",
        "<cipher text output>: where to write the result of encrypting '<plain text input>'")

        # Default values used for demo purposes
        key = 0xaa9fd11416123dcf
        cyphertxtkey = 0xabcdef0123456789
        print(len(int.to_bytes(cyphertxtkey, 8, 'big').hex()))
        cypherpadamt = 29
        plain_text_file = 'plaintext.txt'
        cipher_text_file = 'cyphertext.txt'
        cipher_text_file_output = 'cipher_text_output.txt'
        plain_text_file_output = 'plain_text_output.txt'
    else:
        try:
            # Use command line arguments
            if (len(int.to_bytes(argv[1], 8, 'big').hex()) == 16):
                key = argv[1]
            else:
                print(f"Error, invalid key length. Using default value: {key}")

            if (len(int.to_bytes(argv[2], 8, 'big').hex()) == 16):
                cyphertxtkey = argv[2]
            else:
                print(f"Error, invalid key length. Using default value: {cyphertxtkey}")
            plain_text_file = argv[3]
            cipher_text_file = argv[4]
            cipher_text_file_output = argv[5]
            plain_text_file_output = argv[6]
        except Exception as e:
            # Default values used for demo purposes
            print("An error with input occured, using default values")
            key = 0xaa9fd11416123dcf
            cyphertxtkey = 0xabcdef0123456789
            print(len(int.to_bytes(cyphertxtkey, 8, 'big').hex()))
            cypherpadamt = 29
            plain_text_file = 'plaintext.txt'
            cipher_text_file = 'cyphertext.txt'
            cipher_text_file_output = 'cipher_text_output.txt'
            plain_text_file_output = 'plain_text_output.txt'

    print(f"- - - - - - - - - Beginning Encryption of {plain_text_file} - - - - - - - - -")
    print(int.to_bytes(key, 8, 'big').hex())
    # Pad the plaintext
    try:
        f = open(plain_text_file, mode='r')
        plain_text = f.read()
        f.close()
    except:
        print("Error, could not find plaintext file or file has invalid characters used")

    # Encrypt the data
    cipher, pad_amt = psu_crypt.encrypt(plain_text, key)
    print(f'PAD AMOUNT OF DEFAULT{pad_amt}')
    try:
        f = open(cipher_text_file_output, mode='w').close() # Clean out the cipher_text_file
        f = open(cipher_text_file_output, mode='a')
        for i in range(len(cipher)):
            f.write(f'0x{int.to_bytes(cipher[i], 8, "big").hex()}\n')
        f.close()
    except:
        print("Error, could not find ciphertext file")

    print(f'Encryption complete, file written to: {cipher_text_file}')
    print(f"- - - - - - - - - Finishing Encryption of {plain_text_file} - - - - - - - - -")

    print(f"- - - - - - - - - Beginning Decryption of generated cipher text - - - - - - - - -")
    # Decrypt it
    command_case = psu_crypt.decrypt(cipher, key, pad_amt)
    print(f'Initial Case Decrypted:\n{command_case}')
    print(command_case)
    print(f"- - - - - - - - - Finishing Decryption of generated cipher text - - - - - - - - -")

    # Decrypt from a file
    print(f"- - - - - - - - - Beginning Decryption of {cipher_text_file} - - - - - - - - -")
    # Do file read of cipher text and decrypt it
    lst_decrypt = []

    # Decrypt the written file
    try:
        with open(cipher_text_file, mode='r') as f:
            for to_decrypt in f:
                lst_decrypt.append(int(to_decrypt[:-1], 16))
    except Exception as e:
        print("Error, could not find ciphertext file")
        print(e)

    print(f'Values to Decrypt List:\n {lst_decrypt}')
    ret = psu_crypt.decrypt(lst_decrypt, cyphertxtkey, cypherpadamt)
    print("Final plain text:")
    print(ret)
    # Write the file
    f = open(plain_text_file_output, mode='w')
    f.write(ret[:-cypherpadamt])
    f.close()
    print(f'Decryption complete, file written to: {cipher_text_file}')
    print(f'Output written to: {plain_text_file_output}')
    print(f"- - - - - - - - - Finishing Decryption of {cipher_text_file} - - - - - - - - -")


    pass

if __name__ == '__main__':
    main(argv)