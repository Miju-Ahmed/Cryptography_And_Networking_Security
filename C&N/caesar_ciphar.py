def encrypt(pt, shift):
    ct = ""
    for char in pt:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            en = chr((ord(char) - offset+shift)%26+offset)
            ct += en
        else:
            ct += char
    return ct
def decrypt(ct, shift):
    return encrypt(ct, -shift)
plaintext="Miju Ahmed"
ct = encrypt(plaintext, 5)
dt = decrypt(ct, 5)
print(f"Plaintext : {plaintext}")
print(f"Cipher text : {ct}")
print(f"Decrypt : {dt}")