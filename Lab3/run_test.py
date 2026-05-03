"""
Lab3: 基于Shamir秘密共享的安全多方平均值计算 - 测试脚本
"""
import os, importlib
import ss_function as ss_f

p = 1000000007
test_data = {1: 10, 2: 20, 3: 30}
expected_avg = sum(test_data.values()) // 3

# 清理旧文件
for f in os.listdir('.'):
    if (f.startswith('student_') or f.startswith('d_')) and f.endswith('.txt'):
        os.remove(f)

print("=" * 55)
print("  基于Shamir秘密共享的安全多方平均值计算")
print(f"  输入: Student1={test_data[1]}, Student2={test_data[2]}, Student3={test_data[3]}")
print(f"  预期平均值: {expected_avg}")
print("=" * 55)

# ── 步骤1：秘密份额分发 ──────────────────────────────
print("\n【步骤1】秘密份额分发")
for sid in [1, 2, 3]:
    s = test_data[sid]
    f = ss_f.get_polynomial(s, 1, p, str(sid))
    shares = [ss_f.count_polynomial(f, x, p) for x in [1, 2, 3]]
    for j in range(1, 4):
        with open(f"student_{sid}_{j}.txt", "w") as fp:
            fp.write(str(shares[j-1]))
    print(f"  Student{sid}: f{sid}(x)={s}+{f[1]}x  "
          f"份额=({shares[0]}, {shares[1]}, {shares[2]})")

# ── 步骤2：本地聚合 ──────────────────────────────────
print("\n【步骤2】本地聚合")
d = {}
for sid in [1, 2, 3]:
    vals = []
    for i in [1, 2, 3]:
        with open(f"student_{i}_{sid}.txt") as fp:
            vals.append(int(fp.read()))
    d[sid] = sum(vals) % p
    with open(f"d_{sid}.txt", "w") as fp:
        fp.write(str(d[sid]))
    print(f"  Student{sid}: d_{sid} = {vals[0]}+{vals[1]}+{vals[2]} mod p = {d[sid]}")

# ── 步骤3：计票端重构 ────────────────────────────────
print("\n【步骤3】计票端 - 拉格朗日插值重构")
total = ss_f.restructure_polynomial([2, 3], [d[2], d[3]], 2, p)
inv_3 = pow(3, p - 2, p)
avg = (total * inv_3) % p
print(f"  取 d_2={d[2]}, d_3={d[3]}")
print(f"  重构总和 F(0) = {total}")
print(f"  平均值 = {total} * 3^(-1) mod p = {avg}")

# ── 验证 ─────────────────────────────────────────────
print("\n" + "=" * 55)
status = "✓ 测试通过" if avg == expected_avg else "✗ 测试失败"
print(f"  {status}！  平均值 = {avg}  (预期 {expected_avg})")
print("=" * 55)
