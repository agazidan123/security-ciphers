import tkinter as tk
from tkinter import ttk
from collections import OrderedDict
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

def caesar_cipher(text, key, encrypt=True):
    result = ''
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            offset = (ord(char) - base + key) % 26
            result += chr(base + offset)
        else:
            result += char
    return result

def monoalphabetic_cipher(text, key, encrypt=True):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if encrypt:
        table = str.maketrans(alphabet, key)
    else:
        table = str.maketrans(key, alphabet)
    return text.translate(table)

def prepare_playfair_key(key):
    key = key.upper().replace("J", "I") 
    key_without_duplicates = "".join(OrderedDict.fromkeys(key))
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in key_without_duplicates:
            key_without_duplicates += char
    return key_without_duplicates

def generate_playfair_table(key):
    key = prepare_playfair_key(key)
    table = []
    index = 0
    for _ in range(5):
        row = []
        for _ in range(5):
            row.append(key[index])
            index += 1
        table.append(row)
    return table



def playfair_cipher(text, key, encrypt=True):
    key_table = generate_playfair_table(key)
    if encrypt:
        plaintext = text.upper().replace("J", "I")  
    else:
        plaintext = text.upper()
    plaintext = plaintext.replace(" ", "")
    
    if len(plaintext) % 2 != 0:
        plaintext += 'X'
    
    plaintext_pairs = [plaintext[i:i+2] for i in range(0, len(plaintext), 2)]
    result = ''
    for pair in plaintext_pairs:
        row1, col1 = find_position(key_table, pair[0])
        row2, col2 = find_position(key_table, pair[1])
        if row1 == row2:
            result += key_table[row1][(col1 + 1) % 5] + key_table[row2][(col2 + 1) % 5]
        elif col1 == col2:
            result += key_table[(row1 + 1) % 5][col1] + key_table[(row2 + 1) % 5][col2]
        else:
            result += key_table[row1][col2] + key_table[row2][col1]
    return result


def find_position(table, char):
    for i in range(5):
        for j in range(5):
            if table[i][j] == char:
                return i, j
    raise ValueError(f"Character '{char}' not found in the table.")



def vigenere_cipher(text, key, encrypt=True):
    key = key.upper()
    key_length = len(key)
    result = ''
    for i, char in enumerate(text):
        if char.isalpha():
            key_char = key[i % key_length]
            key_offset = ord(key_char) - ord('A')
            if encrypt:
                shift = (ord(char) + key_offset) % 26
            else:
                shift = (ord(char) - key_offset) % 26
            base = ord('A') if char.isupper() else ord('a')
            result += chr(base + shift)
        else:
            result += char
    return result


def rail_fence_cipher(text, key, encrypt=True):
    if encrypt:
        return ''.join(text[i] for i in range(len(text)) if i % key == 0) + \
               ''.join(text[i] for i in range(len(text)) if i % key == 1) + \
               ''.join(text[i] for i in range(len(text)) if i % key == 2)
    else:
        decrypted_text = [''] * len(text)
        index = 0
        for i in range(len(text)):
            if i % key == 0:
                decrypted_text[i] = text[index]
                index += 1
        for i in range(1, key):
            for j in range(i, len(text), key):
                decrypted_text[j] = text[index]
                index += 1
        return ''.join(decrypted_text)

def row_transposition_cipher(text, key, encrypt=True):
    if encrypt:
        rows = []
        for i in range(0, len(text), key):
            rows.append(text[i:i+key])
        result = ''
        for i in range(key):
            for row in rows:
                if i < len(row):
                    result += row[i]
        return result
    else:
        cols = len(text) // key
        rows = [cols + 1] * (len(text) % key) + [cols] * (key - len(text) % key)
        current_index = 0
        result = ''
        for i in range(cols):
            for j in range(key):
                if i < rows[j]:
                    result += text[current_index]
                    current_index += 1
                else:
                    result += ' '
        return result

def des_encrypt(plain_text, key):
    des = DES.new(key.encode(), DES.MODE_ECB)
    padded_plain_text = pad(plain_text.encode(), DES.block_size)
    cipher_text = des.encrypt(padded_plain_text)
    return cipher_text.hex()

def des_decrypt(cipher_text, key):
    des = DES.new(key.encode(), DES.MODE_ECB)
    decrypted_text = des.decrypt(bytes.fromhex(cipher_text))
    return unpad(decrypted_text, DES.block_size).decode()
def aes_encrypt(plain_text, key):
    return plain_text[::-1]  

def aes_encrypt(plain_text, key):
    aes = AES.new(key.encode(), AES.MODE_ECB)
    padded_plain_text = pad(plain_text.encode(), AES.block_size)
    cipher_text = aes.encrypt(padded_plain_text)
    return cipher_text.hex()

def aes_decrypt(cipher_text, key):
    aes = AES.new(key.encode(), AES.MODE_ECB)
    decrypted_text = aes.decrypt(bytes.fromhex(cipher_text))
    return unpad(decrypted_text, AES.block_size).decode()
# GUI
def on_encrypt():
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    selected_cipher = cipher_combo.get()

    if selected_cipher == "Caesar":
        ciphertext = caesar_cipher(plaintext, int(key))
    elif selected_cipher == "Monoalphabetic":
        ciphertext = monoalphabetic_cipher(plaintext, key)
    elif selected_cipher == "Playfair":
        ciphertext = playfair_cipher(plaintext, key)
    elif selected_cipher == "Vigenere":
        ciphertext = vigenere_cipher(plaintext, key)
    elif selected_cipher == "Rail Fence":
        ciphertext = rail_fence_cipher(plaintext, int(key))
    elif selected_cipher == "Row Transposition":
        ciphertext = row_transposition_cipher(plaintext, int(key))
    elif selected_cipher == "DES":
        ciphertext = des_encrypt(plaintext, key) 
    elif selected_cipher == "AES":
        ciphertext = aes_encrypt(plaintext, key)  
   

    ciphertext_entry.delete(0, tk.END)
    ciphertext_entry.insert(tk.END, ciphertext)

def on_decrypt():
    ciphertext = ciphertext_entry.get()
    key = key_entry.get()
    selected_cipher = cipher_combo.get()

    if selected_cipher == "Caesar":
        plaintext = caesar_cipher(ciphertext, -int(key))
    elif selected_cipher == "Monoalphabetic":
        plaintext = monoalphabetic_cipher(ciphertext, key, False)
    elif selected_cipher == "Playfair":
        plaintext = playfair_cipher(ciphertext, key, False)
    elif selected_cipher == "Vigenere":
        plaintext = vigenere_cipher(ciphertext, key, False)
    elif selected_cipher == "Rail Fence":
        plaintext = rail_fence_cipher(ciphertext, int(key), False)
    elif selected_cipher == "Row Transposition":
        plaintext = row_transposition_cipher(ciphertext, int(key), False)
    elif selected_cipher == "DES":
        plaintext = des_decrypt(ciphertext, key)  
    elif selected_cipher == "AES":
        plaintext = aes_decrypt(ciphertext, key) 

    plaintext_entry.delete(0, tk.END)
    plaintext_entry.insert(tk.END, plaintext)

root = tk.Tk()
root.title("Cipher Program")

frame = ttk.Frame(root, padding="10")
frame.grid(column=0, row=0, sticky=("N", "W", "E", "S"))

tk.Label(frame, text="Plaintext:").grid(row=0, column=0, sticky='w')
plaintext_entry = ttk.Entry(frame)
plaintext_entry.grid(row=0, column=1)

tk.Label(frame, text="Key:").grid(row=1, column=0, sticky='w')
key_entry = ttk.Entry(frame)
key_entry.grid(row=1, column=1)

tk.Label(frame, text="Ciphertext:").grid(row=2, column=0, sticky='w')
ciphertext_entry = ttk.Entry(frame)
ciphertext_entry.grid(row=2, column=1)

cipher_combo = ttk.Combobox(frame, values=["Caesar", "Monoalphabetic", "Playfair", "Vigenere", "Rail Fence", "Row Transposition", "DES", "AES"]) # Add other ciphers here...
cipher_combo.grid(row=3, column=0, columnspan=2, pady=5)

encrypt_button = ttk.Button(frame, text="Encrypt", command=on_encrypt)
encrypt_button.grid(row=4, column=0, pady=5)

decrypt_button = ttk.Button(frame, text="Decrypt", command=on_decrypt)
decrypt_button.grid(row=4, column=1, pady=5)

root.mainloop()
