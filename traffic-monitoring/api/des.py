# Initial Permutation (IP) Table
initial_permutation_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (FP) Table
final_permutation_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Permutation Choice 1 (PC-1) Table
pc1_table = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permutation Choice 2 (PC-2) Table
pc2_table = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

# Left Shifts Table
left_shifts = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]

# S-boxes definition
s_boxes = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]

# Expansion Table
expansion_table = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

# Permutation P Table
p_table = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

def hex_to_bin(hex_str):
    hex_str = hex_str.zfill(16) 
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)

def bin_to_hex(bin_str):
    return hex(int(bin_str, 2))[2:].upper()

# Function for initial permutation
def initial_permutation(plain_text):
    return ''.join(plain_text[initial_permutation_table[i] - 1] for i in range(64))

# Function for final permutation
def final_permutation(text):
    return ''.join(text[final_permutation_table[i] - 1] for i in range(64))

# Function to perform permutation choice 1
def permutation_choice_1(key):
    return ''.join(key[pc1_table[i] - 1] for i in range(56))

# Function to perform permutation choice 2
def permutation_choice_2(cd):
    return ''.join(cd[pc2_table[i] - 1] for i in range(48))

# Function for circular left shifts
def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]

# Function for S-box substitution
def s_box_substitution(xor_bits):
    final_output = ''
    for i in range(8):
        segment = xor_bits[i * 6:(i + 1) * 6]
        row = int(segment[0] + segment[5], 2)
        col = int(segment[1:5], 2)
        value = s_boxes[i][row][col]
        final_output += format(value, '04b')
    return final_output

# Function for permutation P
def permutation_p(sbox_output):
    return ''.join(sbox_output[p_table[i] - 1] for i in range(32))

# Expansion function (E) to expand 32 bits to 48 bits
def bit_expansion(right):
    return ''.join(right[expansion_table[i] - 1] for i in range(48))

# DES Feistel function
def feistel_function(r, k):
    expanded_r = bit_expansion(r)
    xor_output = ''.join(str(int(expanded_r[i]) ^ int(k[i])) for i in range(48))
    sbox_output = s_box_substitution(xor_output)
    return permutation_p(sbox_output), expanded_r, xor_output, sbox_output

def pad(text):
    padding_len = 8 - (len(text) % 8)  # Padding for 8-byte blocks
    return text + chr(padding_len) * padding_len

def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

def text_to_hex(text):
    padded_text = pad(text)  # Pad the text first
    return ''.join([format(ord(c), '02x') for c in padded_text])

def pad_key(key_hex):
    return key_hex.zfill(16)  # Pad the key to ensure it has 16 hex characters

def des_encrypt(plaintext_text, key_hex):
    # Convert plaintext to hex with padding
    plaintext_hex = text_to_hex(plaintext_text)

    # Validate input lengths
    if len(plaintext_hex) % 16 != 0:
        raise ValueError("Plaintext must be a multiple of 16 hex characters.")
    
    # Pad the key
    key_hex = pad_key(key_hex)

    # Convert key to binary
    key_bin = hex_to_bin(key_hex)

    # Check the length of the key after PC-1
    key_pc1 = permutation_choice_1(key_bin)
    if len(key_pc1) != 56:
        raise ValueError("Key must be 16 hex characters long (64 bits) after initial permutation.")

    # Convert plaintext to binary
    plaintext_bin = hex_to_bin(plaintext_hex)

    # Initial Permutation
    ip_output = initial_permutation(plaintext_bin)
    L0, R0 = ip_output[:32], ip_output[32:]

    C0, D0 = key_pc1[:28], key_pc1[28:]

    # Generating keys K1 to K16
    keys = []
    for i in range(16):
        C0 = left_shift(C0, left_shifts[i])
        D0 = left_shift(D0, left_shifts[i])
        cd_combined = C0 + D0
        key = permutation_choice_2(cd_combined)
        keys.append(key)
    
    # DES Rounds
    L, R = L0, R0
    for i in range(16):
        temp_R = R
        f_output, exp_output, xor_output, sbox_output = feistel_function(R, keys[i])
        R = ''.join(str(int(L[j]) ^ int(f_output[j])) for j in range(32))
        L = temp_R
        
    # Final permutation
    final_result = final_permutation(R + L)
    
    return bin_to_hex(final_result)
