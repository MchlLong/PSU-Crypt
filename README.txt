Foreword: This is a demonstration of implementing an encryption algorithm and has not been vetted by the Cryptographic Community at large, this has been made for learning purposes, and not to be used in any application.

1) Michael Long, michael.long.code@gmail.com
2) This is my implementation of "PSU-CRYPTO" for CS485 Project 1. It is a cipher which can encrypt and decrypt 64 bit blocks. Currently has some issues with decoding ASCII characters from their hex representation. 
3) Build with: 
Compile with python3 main.py <key> <cypher key> <cypher pad amount> <plain text input> <cypher text input> <plain text output> <cipher text output> 
If no arguments or invalid arguments are provided, it will use default values

4) 
main.py -- Basic application that encrypts and decrypts a few messages
psu_crypt.py -- Implementation of PSU Crypt, including the encryption, decryption, encrypt block, decrypt block, key table, F(), g(), and f() functions.
plaintext.txt -- a plaintext file with some random paragraphs from (https://randomwordgenerator.com/paragraph.php)
cyphertext.txt -- a cipher file that can be run through the decryption algorithm given key and padding, assumes input of 16 hex values in the form '0x...' delimited by newlines

Once run, it will generate by default two files that are the output of:
<plain text input> --> <cipher text output>
<cypher text input> --> <plain text output> 

<key>
<cypher key> 
<cypher pad amount> 
<plain text input> 
<cypher text input>
<plain text output> 
<cipher text output>

"<key>: secret value to use", 
"<cypher key>: whatever key was used to encrypt '<cypher text input>'",
"<cypher pad amount>: whatever amount of characters of padding was used",
"<plain text input>: the text to test the encryption on\n",
"<cypher text input>: the text to test the decryption with, assumes input of 16 hex values in the form '0x...'",
"<plain text output>: where to write the result of decrypting '<cypher text input>'",
"<cipher text output>: where to write the result of encrypting '<plain text input>'")
