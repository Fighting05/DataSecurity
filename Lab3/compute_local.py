"""
Lab3: Shamir秘密共享 - 本地聚合
每个学生读取其他两方给自己的份额，将三个秘密份额相加得到 d_i
"""
import ss_function as ss_f

# 设置模数p
p = 1000000007

print("=" * 60)
print("   基于Shamir秘密共享的安全多方计算")
print("   学生端 - 本地聚合")
print("=" * 60)

# 输入参与方id
id = int(input("请输入参与方id (1/2/3): "))

# Student_id 读取属于自己的秘密份额
# student_j_id.txt 表示 Student_j 给 Student_id 的份额
data = []
print(f"\n学生 {id} 读取来自其他学生的秘密份额：")
for i in range(1, 4):
    with open(f"student_{i}_{id}.txt", "r") as f:
        val = int(f.read())
        data.append(val)
        print(f"  收到来自 Student_{i} 的份额: {val}")

# 计算三个秘密份额的和
d = 0
for i in range(0, 3):
    d = (d + data[i]) % p

print(f"\n本地聚合结果: d_{id} = {data[0]} + {data[1]} + {data[2]} mod p = {d}")

# 将求和后的秘密份额保存到文件 d_id.txt 内
with open(f"d_{id}.txt", "w") as f:
    f.write(str(d))

print(f"\n已将 d_{id} = {d} 保存到 d_{id}.txt")
print("\n" + "=" * 60)
print(f"  学生 {id} 完成本地聚合")
print("=" * 60)