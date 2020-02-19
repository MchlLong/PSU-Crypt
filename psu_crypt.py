# Michael Long
# CS485
# Project #1: Implementing "PSU-CRYPT"
# PSU-CRYPT

from binascii import hexlify
# Constants
LEFT = 0
RIGHT = 1

# 'F-table' used to do permutations
# Accessed via [0 ~ 15, 0 ~ 15] represented in hex
f_table = [
0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46]

def encrypt(data, key):
    """
    Function to encrypt some 'plain text', and output some 'cipher text'. Designed to
    use the 'PSU-CRYPT' algorithm
        Arguments:
            data (str): some data to run through the encryption algorithm
            key  (int): a secret value to generate the subkeys to encrypt with
        Returns:
            ret   ([int]): list of cipher blocks
            pad_amt (int): amount of F's appended to the end to make it fit into 64 bit  blocks
    """

    # Calculate the pad amount
    pad_amt = 64 - len(data) % 64

    # Pad F's to end to make sure the length will fit into 64 bit block sizes
    for i in range(pad_amt):
        data = data + 'F'
    to_encrypt = []
    ret = []
    # Convert into blocks that can be encrypted
    for i in range(len(data) // 8):
        temp = data[i*8:(i+1)*8]
        temp = temp.encode('utf-8')
        temp = int.from_bytes(temp, "big")
        to_encrypt.append(temp)

    # Encrypt the blocks
    for j in range(len(to_encrypt)):
        ret.append(_encrypt_block(to_encrypt[j], key))

        
    # Print the encrypted message, then return it and the amount of padding added
    print(ret)
    return ret, pad_amt

def decrypt(data, key, pad_amt):
    """
    Function to decrypt some 'cipher text', and output the corresponding 'plain text'. Designed to
    use the 'PSU-CRYPT' algorithm
        Arguments:
            data (str): some 'cipher text' that will be decrypted with the key
            key  (int): secret value to generate subkeys to decrypt with
        Returns:
            ret  (str): returns the decrypted message
    """

    # Define empty lists
    ret = []
    plain = []

    # Decrypt each block in the list
    for i in range(len(data)):
        ret.append(int.to_bytes(_decrypt_block(data[i], key), length=8, byteorder='big'))

    # Decode and append to the return
    #for k in ret:
        #plain.append(k.decode('utf-8'))
    print(ret)
    # Join back into one string
    ret = ''.join(plain)

    return ret[:-pad_amt]



def _encrypt_block(data, key):
    """
    Function to encrypt a 64 bit block, and output some 'cipher block'
        Arguments:
            data (int): the 'plain text' as an integer to encrypt into 'cipher text'
            key  (int): the key to generate the 'key table' with
        Returns:
            ret  (int): the resulting 'cipher text' as an integer
    """
    # Variables
    key_table = _keystream(key, 64) # Generate keystream
    wrd_split = _split(data)        # w0 ~ w3 based on the definition of the document
    key_split = _split(key)         # k0 ~ k3 based on the definition of the document 
    r = [0] * 4                     # r0 ~ r3 based on the definition of the document
    round = 0                       # track the round number

    # Whiten the input 
    # w0 ~ w3 XOR k0 ~ k3
    for i in range(4):
        r[i] = wrd_split[i] ^ key_split[i]

    # Do 16 rounds of function "F()"
    for i in range(16):
        f0, f1 = _bigF_function(r[0], r[1], key_table[i], round)
        temp_r0 = r[0]   # Hold onto r0
        temp_r1 = r[1]   # Hold onto r1
        r[0] = r[2] ^ f0 # XOR r2 and f0, swap with r0 for next round
        r[1] = r[3] ^ f1 # XOR r3 and f1, swap with r1 for next round
        r[2] = temp_r0   # Swap r2 and r0
        r[3] = temp_r1   # Swap r3 and r1
        round += 3       # Increment the round for the next call of F
   
    # Undo last swap
    y = [0] * 4
    y[0] = r[2] # y0 is equivelant to c0
    y[1] = r[3] # y1 is equivelant to c1
    y[2] = r[0] # y2 is equivelant to c2
    y[3] = r[1] # y3 is equivelant to c3

    # Whiten the output
    # y0 ~ y3 XOR k0 ~ k3
    cipher_text = [0] * 4
    for i in range(4):
        cipher_text[i] = y[i] ^ key_split[i]
        cipher_text[i] = cipher_text[i] << (64 - (16 * (i+1)))

    return (cipher_text[0] | cipher_text[1] | cipher_text[2] | cipher_text[3])

def _decrypt_block(data, key):
    """
    Function to decrypt a 64 bit block, and output some 'plain text'
        Arguments:
            data (int): the 'cipher text' as an integer to encrypt into 'plain text'
            key  (int): the 'key' to generate the 'key table' with
        Returns:
            ret  (int): the resulting 'plain text' as an integer
    """
    # Setup variables
    key_table = _keystream(key, 64) # Generate keystream
    wrd_split = _split(data)        # r0 ~ r3 based on the definition of the document
    key_split = _split(key)         # k0 ~ k3 based on the definition of the document 
    r = [0] * 4                     # r0 ~ r3 based on the definition of the document
    round = 3 * 15                  # Set round equal to the high point and work backward

    # Whiten the input
    # w0 ~ w3 XOR k0 ~ k3
    for i in range(4):
        r[i] = wrd_split[i] ^ key_split[i]

    # Do 16 rounds of function "F()"
    for i in range(16):
        f0, f1 = _bigF_function(r[0], r[1], key_table[15 - i], round)
        temp_r0 = r[0]   # Hold onto r0
        temp_r1 = r[1]   # Hold onto r1
        r[0] = r[2] ^ f0 # XOR r2 and f0, swap with r0 for next round
        r[1] = r[3] ^ f1 # XOR r3 and f1, swap with r1 for next round
        r[2] = temp_r0   # Swap r2 and r0
        r[3] = temp_r1   # Swap r3 and r1
        round -= 3       # Decrement the round for the next call of F
   
    # Undo last swap
    y = [0] * 4
    y[0] = r[2] # y0 is equivelant to c0
    y[1] = r[3] # y1 is equivelant to c1
    y[2] = r[0] # y2 is equivelant to c2
    y[3] = r[1] # y3 is equivelant to c3

    # Whiten the output
    # y0 ~ y3 XOR k0 ~ k3
    cipher_text = [0] * 4
    for i in range(4):
        cipher_text[i] = y[i] ^ key_split[i]                   
        cipher_text[i] = cipher_text[i] << (64 - (16 * (i + 1)))                 # Shift right to allow the bytes to be concatenated, reduce shift amount in increments of 16
    return (cipher_text[0] | cipher_text[1] | cipher_text[2] | cipher_text[3]) # Concatenate bytes with OR and return

def _bigF_function(r0, r1, key_row, round):
    """
    Function to do a round of 'F()', will obfuscate the data by doing permutations in '_g_function'
    and shifting / modularizing in '_f_function' and '_f2_function'
        Arguments:
            r0        (int): left half of a passed in 32 bit block
            r1        (int): right half of a passed in 32 bit block
            key_row ([int]): Row of subkeys generated from '_keystream'
            round     (int): Current depth in cipher used to pick correct subkey
        Returns:
            f0,f1(int, int): The resulting obfuscated r0 and r1  
    """
    t0 = _g_function(r0, key_row, round)          # Call 'g( )' and pick the subkey at 'round'
    t1 = _g_function(r1, key_row, round + 1)      # Call 'g( )' and pick the subkey at 'round' + 1
    f0 = _f_function(t0, t1, key_row, round + 2)  # Call 'f( )' and pick the subkey at 'round' + 2
    f1 = _f2_function(t0, t1, key_row, round + 2) # Call 'f2()' and pick the subkey at 'round' + 2
    return f0, f1

def _f_function(t0, t1, key_row, round):
    """
    Function to obfuscate and modularize the r0 and r1 value through shifts
    and modulo. Grants the 'trap door' effect for the resulting blocks
        Arguments:
            t0        (int): Left half of half word, temporary value computed by '_g_function'
            t1        (int): Right half of half word, temporary value computed by '_g_function'
            key_row ([int]): Row of subkeys generated from '_keystream'
            round     (int): Current depth in cipher used to pick correct subkey
        Returns
            f0        (int): the output of the function '(t0 + (2 * t1) + conc) % 2**16'
    """
    k_left = key_row[4 * round]         # Pick subkey for left half of concatenated value
    k_right = key_row[4 * round + 1]    # Pick subkey for right half of concatenated value 
    k_left = k_left << 8                # Shift left side over 16 bits to prepare for concatenation
    conc = k_left | k_right             # Concatenate with a bitwise OR
    f0 = (t0 + (2 * t1) + conc) % 2**16 # Compute f0
    return f0

def _f2_function(t0, t1, key_row, round):
    """
    Function to obfuscate and modularize the r0 and r1 value through shifts
    and modulo. Grants the 'trap door' effect for the resulting blocks
        Arguments:
            t0        (int): Left half of half word, temporary value computed by '_g_function'
            t1        (int): Right half of half word, temporary value computed by '_g_function'
            key_row ([int]): Row of subkeys generated from '_keystream'
            round     (int): Current depth in cipher used to pick correct subkey
        Returns
            f1        (int): the output of the function '((2 * t0) + t1 + conc) % 2**16'
    """
    k_left = key_row[4 * round + 2]     # Pick subkey for left half of concatenated value
    k_right = key_row[4 * round + 3]    # Pick subkey for right half of concatenated value 
    k_left = k_left << 8                # Shift left side over 16 bits to prepare for concatenation
    conc = k_left | k_right             # Concatenate with a bitwise OR
    f1 = ((2 * t0) + t1 + conc) % 2**16 # Concatenate with a bitwise OR
    return f1

def _g_function(word, key_row, round):
    """
    Function to permutate t0 and t1 value through applying the 'F-table'. Assigns based on the coordinates
    in hex (e.g 7a is X = 7th row, Y = 10th column). Used to apply diffusion to the cipher block.
        Arguments:
            word      (int): word to pick the row and column from the 'F-table' with
            key_row ([int]): Row of subkeys generated from '_keystream'
            round     (int): Current depth in cipher used to pick correct subkey
        Returns
            ret       (int): the concatenation fo the fifth and sixth permutation of the 'F-table'
    """

    g = [0] * 6 # Generate empty list to hold values of 'g' 

    g[0] = (word >> 8) & 0xFF   # Bitwise shift to seperate 'word' into left half and truncate excess 0's
    g[1] = word & 0xFF          # Bitwise shift to seperate 'word' into right half and truncate excess 0's

    # Repeated loop to generate g[2] ~ g[5] (or equivelant to g3 ~ g6)
    for i in range(4):
        unroll = g[i + 1] ^ key_row[4 * round + i]   # Logical XOR to get coordinate point
        left = (unroll >> 4) & 0xF                   # Bitwise shift to split off row value, truncate excess 0's
        right = unroll & 0xF                         # Bitwise shift to split off column value, truncate excess 0's
        g[i + 2] = f_table[left * 16 + right] ^ g[i] # XOR the 'F-table' value with the previous output of g

    g[4] = (g[4] << 8)  # Bitwise shift to concatenate left and right sides of g[4] and g[5]
    ret = (g[4] | g[5]) # Bitwise OR to concatenate left and right sides of g[4] and g[5]
    return ret

def _keystream(key, key_len = 64):
    """
    Function to generate the 'key table' of subkeys to be used for encryption and decryption
        Arguments:
            key     (int): Secret value used to generate the subkeys, must be a hex length of 16
            key_len (int): Length of the 'key' in Python hex length, default 'key_len' is 64
        Returns:
            ret ([[int]]): Returns a list of rows of subkeys used for encryption
    """

    # Verify that key is 64 bits, 80 bits, or 128 bits
    # Verify that the key's length divides evenly into 
    if (key_len % 8 != 0):
        return -1

    ret = [[]] * 16         # Generate 16 empty rows
    temp_key = key          # Standard shift key used to generate 0 ~ 191 K' values
    temp_key_truncate = 0   # Temporary shift key to do many right shifts to truncate and obtain the proper value
    counter_truncate = 0    # Counter to truncate 'X' bytes where 'X' is two times the counter
    counter_side_swap = 0   # Counter to swap between right half of key and left half of key

    # Loop through all 192 subkeys
    for i in range(192):

        temp_key = (_bit_rotate(temp_key, 64, LEFT))    # Rotate left bit
        temp_key_truncate = temp_key                    # Hold onto a copy to do truncation and several shifts right
        
        # First twelve keys are on right half of keyspace (0 ~ 11)
        if (counter_side_swap < 12):
            # Drop right most two hex values
            for j in range(counter_truncate):   # Number of remaining times to truncate
                for k in range(8):              # Do eight rotations to get to next subkey
                    temp_key_truncate = (_bit_rotate(temp_key_truncate, 64, RIGHT))

        # Remaining twelve keys on the left half of the keyspace (12 ~ 23)
        else:
            # Shift over to drop right half of hex and begin working with left hex
            for j in range(32):
                temp_key_truncate = (_bit_rotate(temp_key_truncate, 64, RIGHT)) # Do 32 rotations to get to initial state of subkeys
            # Drop right most two hex values
            for k in range(counter_truncate):   # Number of remaining times to truncate
                for l in range(8):              # Do eight rotations to get to next subkey
                    temp_key_truncate = (_bit_rotate(temp_key_truncate, 64, RIGHT))
        

        # Update loop control variables and ret value
        add = temp_key_truncate & 0xFF                   # Truncate excess bits to keep the subkeys 32 bits
        ret[i // 16].append(add)                         # Add to return list at row (i // 16), drop remainder
        counter_truncate = (counter_truncate + 1) % 4    # Increase the amount of shifts needed to reach next key block
        counter_side_swap = (counter_side_swap + 1) % 24 # Increase the amount of checks before swapping halves

    return ret # Return list of key blocks

def _bit_rotate(key, key_len, dir):
    """
    Function to rotate a set of bytes to the left or right, take the dropped bit and put it on the respective end
    and truncate excess bytes. Used in this implementation to do 'key' rotations to generate 'sub keys' in the
    'key table'
        Arguments:
            key     (int): Secret value used to generate the subkeys
            dir     (int): The direction to rotate, constant LEFT = 0, constant RIGHT = 1
            key_len (int): Length of the 'key' in Python hex length, default 'key_len' is 64
        Returns:
            ret     (int): Returns the rotated byte stream
    """
    # Rotate left
    if (dir == LEFT):
        left_truncate = (2**key_len) - 2    # Equivelant to 0xFFFF FFFF FFFF FFFE to drop the right most bit
        reg = ((key << 1) & left_truncate)  # Shift left, then drop the rightmost bit
        overflow = key >> (key_len - 1)     # Shift to catch the leftmost bit to put on the righthand bit slot

    # Rotate right
    if (dir == RIGHT):
        right_truncate = 2**(key_len - 1)                   # Equivelant to 0xEFFF FFFF FFFF FFFF FFFF to drop the leftmost bit
        reg = key >> 1                                      # Shift right, then drop the leftmost bit
        overflow = (key << (key_len - 1)) & right_truncate  # Shift to catch the rightmost bit to put on the lefthand bit slot
    
    return (reg | overflow) # Bitwise OR to append the overflow bit to the dropped bit position

def _split(arg):
    """
    Function to take a hex value of length 16 and subdivide it into four pieces. Used to subdivide the word
    to be used in encryption and decryption.
        Arguments:
            arg     (int): Value to sub divide into four values
        Returns:
            ret   ([int]): List of subdivided hex values, whereas ret[0] is the left most hex values

    """
    ret = []
    ret.append((arg >> 48) & 0xFFFF)    # Grab first four hex values
    ret.append((arg >> 32) & 0xFFFF)    # Grab second four hex values
    ret.append((arg >> 16) & 0xFFFF)    # Grab third four hex values
    ret.append((arg >>  0) & 0xFFFF)    # Grab fourth four hex values
    return ret