"""
Lab3: Shamir秘密共享 - 平均值计算
计票员选择任意两个学生，获取他们的 d 值
用拉格朗日插值重构出总和 sum = a + b + c
然后计算平均值 avg = sum / 3
"""
import ss_function as ss_f

# 设置模数p
p = 1000000007

print("=" * 60)
print("   基于Shamir秘密共享的安全多方计算")
print("   计票端 - 平均值计算")
print("=" * 60)

# 随机选取两个参与方，例如 student2 和 student3
# 读取 d2, d3
print("\n计票员选取 Student2 和 Student3 的 d 值进行重构...")
d_23 = []
for i in [2, 3]:
    with open(f"d_{i}.txt", "r") as f:
        val = int(f.read())
        d_23.append(val)
        print(f"  读取 d_{i} = {val}")

# 使用拉格朗日插值恢复 d = a + b + c
# x = [2, 3], fx = [d_2, d_3], t = 2
d = ss_f.restructure_polynomial([2, 3], d_23, 2, p)
print(f"\n重构结果: a + b + c = {d}")

# 计算平均值 avg = d / 3 mod p
# 即 avg = d * inv(3) mod p
inv_3 = pow(3, p - 2, p)  # 3的乘法逆元
avg = (d * inv_3) % p
print(f"\n计算平均值: avg = (a + b + c) / 3 = {d} * {inv_3} mod p = {avg}")

print("\n" + "=" * 60)
print(f"  最终结果: 三人数据的平均值为 {avg}")
print("=" * 60)