import random

def Robin_Miller_prime_test(p,k):
    if p<2:
        return False
    if p in (2,3):
        return True
    if p%2==0:
        return False
    d=p-1
    s=0
    while d%2==0:
        d//=2
        s+=1
    for _ in range(k):
        a=random.randint(2,p-1)
        x=pow(a,d,p)
        if x==1 or x==p-1:
            continue
        for _ in range(s-1):
            x=pow(x,2,p)
            if x==p-1:
                break
            else:
                return False
    return True

if __name__=="__main__":
    P=53
    k=10
    c=Robin_Miller_prime_test(P,k)
    if c:
        print(f"{P} maybe prime.")
    else:
        print(f"{P} is composite.")