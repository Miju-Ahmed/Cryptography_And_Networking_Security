e,d,M,n=79,1019,6880023,3337
M_str = str(M)

msg_block=[]
for i in range(0,len(M_str),3):
    block = M_str[i:i+3]
    msg_block.append(int(block))
print(msg_block)

cipher_block=[]
for m in msg_block:
    c = pow(m,e,n)
    cipher_block.append(c)
print(cipher_block)

cipher_block_concat = ""
for c in cipher_block:
    block = str(c).zfill(4)
    cipher_block_concat+=block
print(cipher_block_concat)

cipher_block=[]
for i in range(0,len(cipher_block_concat), 4):
    block = cipher_block_concat[i:i+4]
    cipher_block.append(int(block))
print(cipher_block)

i=0
decrypted_text=""
for c in cipher_block:
    m = pow(c,d,n)
    if i<len(cipher_block)-1:
        mstr = str(m).zfill(3)
    else:
        remaining_length = len(M_str) - len(decrypted_text)
        mstr = str(m).zfill(remaining_length)
    decrypted_text+=mstr
    i+=1
decrypted_text = decrypted_text[-len(M_str):]
print(decrypted_text)