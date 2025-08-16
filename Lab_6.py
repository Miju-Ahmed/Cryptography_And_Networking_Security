import random

def Lehmann_prime_test(P,k):
    if P<2:
        return False
    if P%2==0:
        return False
    for _ in range(k):
        a=random.randint(2,P-2)
        x=pow(a,(P-1)//2,P)
        if x!=1 and x!=P-1:
            return False
    return True
if __name__=="__main__":
    P=475834758473
    k=10
    c=Lehmann_prime_test(P,k)
    if c:
        print(f"{P} maybe prime.")
    else:
        print(f"{P} is composite.")