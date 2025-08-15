import re
def normalize(text):
    return re.sub('[^A-Z]','',text.upper())
def transposition_encrypt(text, width, pad_char='X'):
    rem = len(text)%width
    if rem!=0:
        text += pad_char*(width-rem)
    rows = len(text)//width
    matrix = [list(text[i*width:(i+1)*width]) for i in range(rows)]
    return ''.join(matrix[r][c] for c in range(width) for r in range(rows))
def transposition_decrypt(ciphertext, width):
    n = len(ciphertext)
    rows = n//width
    matrix = [['']*width for _ in range(rows)]
    idx = 0
    for c in range(width):
        for r in range(rows):
            matrix[r][c] = ciphertext[idx]
            idx+=1
    return ''.join(''.join(row) for row in matrix)

if __name__=="__main__":
    plaintext = "DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLY UNIVERSITY OF RAJSHAHI BANGLADESH"
    width1 = int(input("Enter first width (number of columns): "))
    width2 = int(input("Enter second width (number of columns): "))
    norm_plain=normalize(plaintext)

    c1 = transposition_encrypt(norm_plain, width1)
    print("Ciphertext after single transposition:", c1)
    c2 = transposition_encrypt(c1, width2)
    print("Ciphertext after double transposition:", c2)

    d2 = transposition_decrypt(c2, width2)
    d1 = transposition_decrypt(d2, width1)
    decrypted = d1[:len(norm_plain)]
    print("Decrypted (original, normalized):", decrypted)