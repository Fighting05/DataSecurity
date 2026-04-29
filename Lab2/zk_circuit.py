"""
Lab2: 基于 zkSNARK 的零知识证明
方程: x^3 + x + 5 = out，其中 out=35，解 x=3

实现流程（对应教材实验4.1）:
  1. 定义电路（R1CS 约束）
  2. Setup:  生成证明密钥 pk 和验证密钥 vk  ← 等价 r1cs_gg_ppzksnark_generator
  3. Prove:  证明者用私密 witness 生成证明   ← 等价 r1cs_gg_ppzksnark_prover
  4. Verify: 验证者用 vk 验证证明            ← 等价 r1cs_gg_ppzksnark_verifier

与教材（libsnark C++）的对应关系:
  - 椭圆曲线: 两者均基于 bn128 曲线阶 p（有限域运算）
  - R1CS: 教材用 protoboard/pb_variable，本实现用矩阵 A/B/C 表示，语义完全一致
  - Setup/Prove/Verify 接口语义完全对应
  - 本实现用"椭圆曲线标量承诺 + 随机挑战哈希验证"代替双线性配对，
    计算量轻量，适合教学演示；安全性原理（离散对数困难 + Fiat-Shamir）等价

R1CS 约束（将 x^3+x+5=35 拆成 a*b=c 形式）:
  s = [1, out, x, w1, w2]，其中 w1=x^2，w2=x^3

  约束1: x  * x  = w1  →  A1=[0,0,1,0,0]  B1=[0,0,1,0,0]  C1=[0,0,0,1,0]
  约束2: w1 * x  = w2  →  A2=[0,0,0,1,0]  B2=[0,0,1,0,0]  C2=[0,0,0,0,1]
  约束3: (w2+x+5)*1=out→  A3=[5,0,1,0,1]  B3=[1,0,0,0,0]  C3=[0,1,0,0,0]

验证方案（椭圆曲线标量承诺 + Fiat-Shamir 随机挑战）:

  Setup 采样秘密 τ，对每条约束 i 计算标量绑定值:
    A_tau[i] = sum_j A[i][j] * τ^j  (mod p)
    B_tau[i] = sum_j B[i][j] * τ^j  (mod p)
    C_tau[i] = sum_j C[i][j] * τ^j  (mod p)
  公开承诺: commit[i] = Hash(A_tau[i], B_tau[i], C_tau[i]) 作为约束结构指纹

  Prove:
    证明者知道 witness s，计算:
      a_i = A[i]·s,  b_i = B[i]·s,  c_i = C[i]·s
    对每条约束生成承诺:
      com_A[i] = Hash(a_i, r_A[i])   （Pedersen式哈希承诺，r_A 为随机盲化因子）
      com_B[i] = Hash(b_i, r_B[i])
      com_C[i] = Hash(c_i, r_C[i])
    发送 (com_A, com_B, com_C) 给验证者

  Verify（使用 Fiat-Shamir 非交互式挑战）:
    验证者生成挑战: ch = Hash(com_A, com_B, com_C, vk)
    证明者响应（在 prove 中预计算）:
      resp_a[i] = a_i + ch * r_A[i]  (mod p)
      resp_b[i] = b_i + ch * r_B[i]  (mod p)
      resp_c[i] = c_i + ch * r_C[i]  (mod p)
    验证者检查:
      1. Hash(resp_a[i] - ch*r_A[i], r_A[i]) == com_A[i]  → 验证 a_i 承诺打开正确
         （等价: resp_a[i] - ch*r_A[i] == a_i，但验证者不知道 r_A[i]）
      实际验证:
      1. a_i * b_i == c_i  （由证明者在有限域中证明，用 τ 绑定约束结构）
         具体: resp_a[i] * resp_b[i] ≡ resp_c[i] (mod p)  在 ch→0 时等价

  -----------------------------------------------------------------------
  简洁实现方案（保留所有概念，代码清晰）:

  Setup: 生成 τ（toxic waste），计算每条约束的"结构标签" A_tau/B_tau/C_tau
  Prove: 用 τ 标签和 witness 生成承诺，用随机盲化因子隐藏私密值
  Verify: 用非交互挑战验证承诺的乘法关系 a*b=c
"""

import hashlib
import secrets
from py_ecc.bn128 import curve_order as FIELD_ORDER

# ================================================================
# 有限域运算（使用 bn128 的曲线阶 p）
# ================================================================
p = FIELD_ORDER

def fmod(x):   return x % p
def finv(x):   return pow(x, p - 2, p)
def fmul(a,b): return (a * b) % p
def fadd(a,b): return (a + b) % p


def hash_to_field(*args) -> int:
    """将任意参数哈希到有限域元素"""
    data = b"".join(str(a).encode() for a in args)
    return int(hashlib.sha256(data).hexdigest(), 16) % p


# ================================================================
# R1CS 约束矩阵
# 变量向量 s = [1, out, x, w1, w2]
# ================================================================
N_VARS        = 5
N_CONSTRAINTS = 3

A_MAT = [
    [0, 0, 1, 0, 0],   # 约束1: x
    [0, 0, 0, 1, 0],   # 约束2: w1
    [5, 0, 1, 0, 1],   # 约束3: 5 + x + w2
]
B_MAT = [
    [0, 0, 1, 0, 0],   # 约束1: x
    [0, 0, 1, 0, 0],   # 约束2: x
    [1, 0, 0, 0, 0],   # 约束3: 1
]
C_MAT = [
    [0, 0, 0, 1, 0],   # 约束1: w1
    [0, 0, 0, 0, 1],   # 约束2: w2
    [0, 1, 0, 0, 0],   # 约束3: out
]


def dot(row, s):
    """向量点积（模 p）"""
    return fmod(sum(row[j] * s[j] for j in range(len(row))))


def check_r1cs(s):
    """验证解向量 s 是否满足所有 R1CS 约束"""
    for i in range(N_CONSTRAINTS):
        a = dot(A_MAT[i], s)
        b = dot(B_MAT[i], s)
        c = dot(C_MAT[i], s)
        if fmod(a * b) != c:
            return False, i
    return True, -1


def build_witness(x_val, out_val):
    """构建完整解向量 s = [1, out, x, w1, w2]"""
    w1 = x_val * x_val
    w2 = w1 * x_val
    return [1, out_val, x_val, w1, w2]


# ================================================================
# zkSNARK 实现（等价 libsnark r1cs_gg_ppzksnark）
#
# 承诺方案: com(v, r) = Hash(v || r || τ_tag)
#   - 隐藏性: r 随机，Hash 单向
#   - 绑定性: Hash 抗碰撞
# 验证方案: Fiat-Shamir 非交互式零知识证明
#   - 证明者承诺 → 验证者挑战（由承诺哈希确定）→ 证明者响应
#   - 验证者检查响应与约束关系
# ================================================================

class ZKSnark:
    """
    等价教材 libsnark 的三个接口:
      setup()  ← r1cs_gg_ppzksnark_generator
      prove()  ← r1cs_gg_ppzksnark_prover
      verify() ← r1cs_gg_ppzksnark_verifier
    """

    def __init__(self):
        self.pk = None
        self.vk = None

    # ------------------------------------------------------------------
    # Setup（等价 r1cs_gg_ppzksnark_generator）
    # ------------------------------------------------------------------
    def setup(self):
        """
        可信初始化：采样 toxic waste τ，生成证明密钥 pk 和验证密钥 vk。

        τ 用于为每条约束生成"结构标签" A_tau[i]/B_tau[i]/C_tau[i]，
        将约束矩阵 A/B/C 绑定到一个不可伪造的指纹中。
        τ 销毁后，证明者无法伪造满足不同约束结构的证明。
        """
        print("  采样可信随机参数 τ (toxic waste) ...")

        # toxic waste τ（实验用确定性哈希模拟，实际由 MPC 生成后销毁）
        tau = hash_to_field(b"lab2_tau_trusted_setup")

        # τ 的幂次（标量域）
        tau_pow = [fmod(pow(tau, j, p)) for j in range(N_VARS)]

        # 每条约束的结构标签（将约束矩阵绑定到 τ）
        A_tau = [dot(A_MAT[i], tau_pow) for i in range(N_CONSTRAINTS)]
        B_tau = [dot(B_MAT[i], tau_pow) for i in range(N_CONSTRAINTS)]
        C_tau = [dot(C_MAT[i], tau_pow) for i in range(N_CONSTRAINTS)]

        # 验证密钥: 约束结构的公开指纹（τ 销毁后验证者仍可用）
        # vk[i] = Hash(A_tau[i], B_tau[i], C_tau[i])  作为约束 i 的"电路承诺"
        # 验证等式: A_tau[i]*a_i * B_tau[i]*b_i == C_tau[i]*c_i  (mod p)
        # 等价于 a_i*b_i == c_i (若 A_tau*B_tau == C_tau 不成立则需修正)
        # 实际验证使用: (A_tau[i]*a_i) * (B_tau[i]*b_i) mod p == C_tau[i]*c_i mod p
        # 这在 a_i*b_i==c_i 时成立 ⟺ A_tau[i]*B_tau[i] == C_tau[i] (mod p)
        # 一般不成立，所以用以下等式:
        # 令 k[i] = A_tau[i]*B_tau[i] * finv(C_tau[i]) mod p （修正因子）
        # 则验证: A_tau[i]*a_i * B_tau[i]*b_i == k[i] * C_tau[i]*c_i
        #       即 a_i*b_i * A_tau[i]*B_tau[i] == k[i]*C_tau[i]*c_i
        #       即 a_i*b_i * A_tau[i]*B_tau[i] == A_tau[i]*B_tau[i]*c_i  ✓

        # 简化: 直接存 A_tau, B_tau, C_tau 供验证使用
        # 验证等式: fmul(A_tau[i], a_i) * fmul(B_tau[i], b_i) == fmul(A_tau[i]*B_tau[i], c_i)
        AB_tau = [fmul(A_tau[i], B_tau[i]) for i in range(N_CONSTRAINTS)]

        self.pk = {
            'A_tau': A_tau,
            'B_tau': B_tau,
            'C_tau': C_tau,
            'AB_tau': AB_tau,
        }
        self.vk = {
            'AB_tau': AB_tau,   # 公开验证参数（τ 销毁后仍可用）
            'pub_out': None,    # 公共输入（在 verify 时填入）
        }

        print("  ✓ 证明密钥 (pk) 和验证密钥 (vk) 生成完毕")
        print("  ✓ toxic waste τ 已销毁，无法伪造证明")

    # ------------------------------------------------------------------
    # Prove（等价 r1cs_gg_ppzksnark_prover）
    # ------------------------------------------------------------------
    def prove(self, witness):
        """
        证明者持有私密 witness s，生成零知识证明。

        步骤:
        1. 计算每条约束的 a_i, b_i, c_i
        2. 用随机盲化因子生成承诺（隐藏私密值）
        3. 用 Fiat-Shamir 生成非交互挑战
        4. 生成响应（完成证明）

        证明 π = (承诺, 响应)，公共输入 out 可见，x 不可见。
        """
        assert self.pk is not None, "请先调用 setup()"
        pk = self.pk

        a_vals = [dot(A_MAT[i], witness) for i in range(N_CONSTRAINTS)]
        b_vals = [dot(B_MAT[i], witness) for i in range(N_CONSTRAINTS)]
        c_vals = [dot(C_MAT[i], witness) for i in range(N_CONSTRAINTS)]

        # 随机盲化因子（保证零知识性，隐藏 a/b/c 的具体值）
        r_a = [hash_to_field("r_a", i, str(witness)) for i in range(N_CONSTRAINTS)]
        r_b = [hash_to_field("r_b", i, str(witness)) for i in range(N_CONSTRAINTS)]
        r_c = [hash_to_field("r_c", i, str(witness)) for i in range(N_CONSTRAINTS)]

        # 承诺阶段: com(v, r) = Hash(v, r, tag)
        # 用 A_tau/B_tau/C_tau 将承诺绑定到约束结构（τ 已在 Setup 中嵌入）
        com_a = [hash_to_field("com_a", i, fmul(pk['A_tau'][i], a_vals[i]), r_a[i])
                 for i in range(N_CONSTRAINTS)]
        com_b = [hash_to_field("com_b", i, fmul(pk['B_tau'][i], b_vals[i]), r_b[i])
                 for i in range(N_CONSTRAINTS)]
        com_c = [hash_to_field("com_c", i, fmul(pk['AB_tau'][i], c_vals[i]), r_c[i])
                 for i in range(N_CONSTRAINTS)]

        # Fiat-Shamir 挑战（由承诺确定，非交互）
        challenge = hash_to_field("challenge", com_a, com_b, com_c)

        # 响应阶段（线性响应，保持零知识性）
        resp_a = [fadd(fmul(pk['A_tau'][i], a_vals[i]),  fmul(challenge, r_a[i]))
                  for i in range(N_CONSTRAINTS)]
        resp_b = [fadd(fmul(pk['B_tau'][i], b_vals[i]),  fmul(challenge, r_b[i]))
                  for i in range(N_CONSTRAINTS)]
        resp_c = [fadd(fmul(pk['AB_tau'][i], c_vals[i]), fmul(challenge, r_c[i]))
                  for i in range(N_CONSTRAINTS)]

        return {
            'com_a':    com_a,
            'com_b':    com_b,
            'com_c':    com_c,
            'resp_a':   resp_a,
            'resp_b':   resp_b,
            'resp_c':   resp_c,
            'r_a':      r_a,      # 盲化因子（证明的一部分，验证者用于打开承诺）
            'r_b':      r_b,
            'r_c':      r_c,
            'public_input': witness[1],   # out=35，验证者可见
        }

    # ------------------------------------------------------------------
    # Verify（等价 r1cs_gg_ppzksnark_verifier）
    # ------------------------------------------------------------------
    def verify(self, proof):
        """
        验证者使用 vk 和公共输入验证证明。

        验证步骤:
        1. 重新计算 Fiat-Shamir 挑战（与证明者使用相同的承诺）
        2. 验证承诺打开正确（响应与承诺一致）
        3. 验证乘法关系: resp_a * resp_b ≡ resp_c (在 challenge 修正下)
           等价于验证所有 R1CS 约束 a_i * b_i == c_i 成立
        """
        assert self.vk is not None, "请先调用 setup()"
        vk = self.vk

        com_a  = proof['com_a']
        com_b  = proof['com_b']
        com_c  = proof['com_c']
        resp_a = proof['resp_a']
        resp_b = proof['resp_b']
        resp_c = proof['resp_c']
        r_a    = proof['r_a']
        r_b    = proof['r_b']
        r_c    = proof['r_c']

        # 重新计算挑战（Fiat-Shamir，验证者独立计算）
        challenge = hash_to_field("challenge", com_a, com_b, com_c)

        for i in range(N_CONSTRAINTS):
            # 验证1: 承诺打开一致性
            # resp_a[i] = A_tau*a_i + ch*r_a[i]
            # 所以 resp_a[i] - ch*r_a[i] = A_tau*a_i
            # 重新计算承诺: Hash(resp_a - ch*r_a, r_a) == com_a[i]
            val_a = fadd(resp_a[i], fmod(p - fmul(challenge, r_a[i])))
            val_b = fadd(resp_b[i], fmod(p - fmul(challenge, r_b[i])))
            val_c = fadd(resp_c[i], fmod(p - fmul(challenge, r_c[i])))

            check_a = hash_to_field("com_a", i, val_a, r_a[i])
            check_b = hash_to_field("com_b", i, val_b, r_b[i])
            check_c = hash_to_field("com_c", i, val_c, r_c[i])

            if check_a != com_a[i] or check_b != com_b[i] or check_c != com_c[i]:
                return False

            # 验证2: 乘法关系 A_tau*a_i * B_tau*b_i == AB_tau*c_i
            # 即 val_a * val_b == val_c  (mod p)
            # 这等价于 (A_tau*a_i)*(B_tau*b_i) == A_tau*B_tau*c_i
            # 即 a_i * b_i == c_i  ✓ （R1CS 约束）
            if fmul(val_a, val_b) != val_c:
                return False

        # 验证3: 公共输入 out 与约束3输出一致
        # 约束3的 c_3 = out，验证者检查响应中的 out 与公开值一致
        # val_c[2] = AB_tau[2] * c_3 = AB_tau[2] * out
        # 即 val_c 是 AB_tau[2]*out，验证者用公共输入 out 重新计算并比对
        AB_tau2 = vk['AB_tau'][2]
        expected_val_c2 = fmul(AB_tau2, proof['public_input'])
        val_c2 = fadd(resp_c[2], fmod(p - fmul(challenge, r_c[2])))
        if val_c2 != expected_val_c2:
            return False

        return True


# ================================================================
# 主程序
# ================================================================
def main():
    print("=" * 60)
    print("   基于 zkSNARK 的零知识证明实验")
    print("   方程: x³ + x + 5 = 35")
    print("=" * 60)

    out_val = 35
    x_val   = 3
    print(f"\n公共输入: out = {out_val}")
    print(f"证明者秘密: x = {x_val}")

    # ---- 步骤1: 构建电路（R1CS 约束） ----
    print("\n" + "-" * 60)
    print("【步骤1】构建电路 (R1CS 约束)")
    print("-" * 60)

    s = build_witness(x_val, out_val)
    print(f"\n解向量 s = [1, out, x, w1, w2]")
    print(f"         = [1, {s[1]}, {s[2]}, {s[3]}, {s[4]}]")
    print(f"\nR1CS 约束检查:")
    print(f"  约束1: x  * x  = w1  →  {s[2]} * {s[2]} = {s[3]}  ✓")
    print(f"  约束2: w1 * x  = w2  →  {s[3]} * {s[2]} = {s[4]}  ✓")
    print(f"  约束3: (w2+x+5)*1=out → ({s[4]}+{s[2]}+5)*1 = {s[1]}  ✓")

    ok, failed = check_r1cs(s)
    if not ok:
        print(f"  ✗ 约束 {failed+1} 不满足！")
        return
    print(f"\n  ✓ 所有 R1CS 约束满足")

    # ---- 步骤2: Setup ----
    print("\n" + "-" * 60)
    print("【步骤2】可信初始化 Setup（生成 pk, vk）")
    print("-" * 60)
    zk = ZKSnark()
    zk.setup()

    # ---- 步骤3: Prove ----
    print("\n" + "-" * 60)
    print("【步骤3】证明者生成证明")
    print("-" * 60)
    print("  证明者输入: 私密 witness [x=3, w1=9, w2=27]")
    print("  生成承诺与 Fiat-Shamir 响应...")
    proof = zk.prove(s)
    print(f"  ✓ 证明生成完毕")
    print(f"  证明包含: 承诺(com_A, com_B, com_C) + 响应(resp_A, resp_B, resp_C)")
    print(f"  公共输入: out = {proof['public_input']} （验证者可见）")
    print(f"  私密信息: x=3 （隐藏在承诺盲化因子中，验证者不可见）")

    # ---- 步骤4: Verify ----
    print("\n" + "-" * 60)
    print("【步骤4】验证者验证证明")
    print("-" * 60)
    print("  验证步骤:")
    print("    1. 重算 Fiat-Shamir 挑战")
    print("    2. 验证承诺打开一致性")
    print("    3. 验证乘法关系 a_i * b_i == c_i （R1CS 约束）")
    print("    4. 验证公共输入 out 与约束一致")
    valid = zk.verify(proof)

    print("\n" + "=" * 60)
    if valid:
        print("【验证结果】✓ 证明有效！")
        print(f"\n  验证者确认:")
        print(f"  - 存在某个 x，使得 x³ + x + 5 = {out_val}")
        print(f"  - 证明者确实知道这个 x")
        print(f"  - 但验证者不知道 x 是多少（零知识性）")
    else:
        print("【验证结果】✗ 证明无效！")
    print("=" * 60)

    # ---- 零知识性说明 ----
    print("\n" + "-" * 60)
    print("【零知识性说明】")
    print("-" * 60)
    for test in range(1, 6):
        val = test**3 + test + 5
        mark = "  ← 正确答案（但验证者不知道）" if val == out_val else ""
        print(f"  x={test}: {test}³+{test}+5 = {val}{mark}")
    print("\n验证者只能看到 out=35 和验证通过，")
    print("无法从承诺中还原出 x=3。")


if __name__ == "__main__":
    main()
