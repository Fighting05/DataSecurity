import random

# 快速幂计算 a^b % p
def quickpower(a, b, p):
    a = a % p
    ans = 1
    while b != 0:
        if b & 1:
            ans = (ans * a) % p
        b >>= 1
        a = (a * a) % p
    return ans

# 构建多项式：x0为常数项系数，T为最高次项次数，p为模数，fname为多项式名
def get_polynomial(x0, T, p, fname):
    f = []
    f.append(x0)
    for i in range(0, T):
        f.append(random.randrange(0, p))
    return f

# 计算多项式值
def count_polynomial(f, x, p):
    ans = f[0]
    for i in range(1, len(f)):
        ans = (ans + f[i] * quickpower(x, i, p)) % p
    return ans

# 重构函数f并返回f(0)（使用拉格朗日插值）
def restructure_polynomial(x, fx, t, p):
    ans = 0
    # 利用多项式插值法计算出 x=0 时多项式的值
    for i in range(0, t):
        fx[i] = fx[i] % p
        fxi = 1
        # 在模p下，(a/b)%p = (a*c)%p，其中 c 为 b 在模p下的逆元，c = b^(p-2)%p
        for j in range(0, t):
            if j != i:
                fxi = (-1 * fxi * x[j] * quickpower(x[i] - x[j], p - 2, p)) % p
        fxi = (fxi * fx[i]) % p
        ans = (ans + fxi) % p
    return ans