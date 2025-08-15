import re
def normalize(text):
    return re.sub('[^A-Z]','',text.upper())
def transposition_encrypt(plaintext, width,pad_char='X'):
    text = normalize(plaintext)
    rem = len(text)%width
    if rem!=0:
        text += pad_char*(width-rem)
    rows = len(text)//width
    matrix = [list(text[i*width:(i+1)*width]) for i in range(rows)]
    ciphertext = ''.join(matrix[r][c] for c in range(width) for r in range(rows))
    return ciphertext
def transposition_decrypt(ciphertext, width):
    n = len(ciphertext)
    rows = n//width
    matrix = [['']*width for _ in range(rows)]
    idx = 0
    for c in range(width):
        for r in range(rows):
            matrix[r][c] = ciphertext[idx]
            idx+=1
    padded_plain = ''.join(''.join(row) for row in matrix)
    return padded_plain
if __name__=="__main__":
    plaintext = "DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLY UNIVERSITY OF RAJSHAHI BANGLADESH"
    width = int(input("Enter width (number of columns): "))

    cipher = transposition_encrypt(plaintext, width)
    print("Ciphertext:", cipher)

    decrypted_padded = transposition_decrypt(cipher, width)

    # Remove any trailing padding X's that were added
    normalized_original = normalize(plaintext)
    decrypted = decrypted_padded[:len(normalized_original)]
    print("Decrypted (original, normalized):", decrypted)