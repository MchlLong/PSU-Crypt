README
1) Michael Long, michlong@pdx.edu
2) This is my implementation of "PSU-CRYPTO" for CS485 Project 1. It is a cipher which can encrypt and decrypt 64 bit blocks. Currently has some issues with decoding ASCII characters from their hex representation. 
3) Build with: python3 main.py "plain_text" "cipher_text", plain_text and cipher_text if left blank will default to "plaintext.txt" and "cyphertext.txt" respectively
4) 
main.py -- Basic application that encrypts and decrypts a few messages
psu_crypt.py -- Implementation of PSU Crypt, including the encryption, decryption, encrypt block, decrypt block, key table, F(), g(), and f() functions.
plaintext.txt -- a plaintext file with some random paragraphs from (https://randomwordgenerator.com/paragraph.php)
ciphertext.txt -- example output of the encrypt of the plaintext