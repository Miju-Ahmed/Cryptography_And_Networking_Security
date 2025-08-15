def caesar_encrypt(text,shift):
    result=""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result+=chr((ord(char)-65+shift)%26+65)
            else:
                result+=chr((ord(char)-97+shift)%26+97)
        else:
            result+=char
    return result
def caesar_decrypt(text,shift):
    return caesar_encrypt(text,-shift)
if __name__=="__main__":
    plain_text=input("Enter the plaintext: ")
    shift=3
    cipher_text=caesar_encrypt(plain_text,shift)
    decrypt_text=caesar_decrypt(cipher_text,shift)
    print(f"Plaintext   : {plain_text}")
    print(f"Ciphertext  : {cipher_text}")
    print(f"Decrypttext : {decrypt_text}")