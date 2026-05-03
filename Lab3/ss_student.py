"""
Lab3: Shamir秘密共享 - 学生端
每个学生将自己的私有数据通过 (2,3) Shamir 秘密共享分享给另外两个学生
"""
import ss_function as ss_f

# 设置模数p
p = 1000000007

print("=" * 60)
print("   基于Shamir秘密共享的安全多方计算")
print("   学生端 - 秘密份额分发")
print("=" * 60)

# 输入参与方id以及秘密s
id = int(input("请输入参与方id (1/2/3): "))
s = int(input(f"请输入 student_{id} 的私有数据 s: "))

print(f"\n学生{id}的私有数据: {s}")

# 秘密份额为 (share_x, share_y)
shares_x = [1, 2, 3]
shares_y = []

# 计算多项式及秘密份额 (t=1, n=3)
# 构造多项式 f(x) = s + r1*x，其中 r1 是随机系数
print(f"\nStudent_{id} 的多项式及秘密份额：")
f = ss_f.get_polynomial(s, 1, p, str(id))

temp = []
for j in range(0, 3):
    val = ss_f.count_polynomial(f, shares_x[j], p)
    print(f"  份额 ({shares_x[j]}, {val})")
    temp.append(val)
    shares_y.append(val)

# Student_id 将自己的投票值的秘密份额分享给另外两个学生
# 将三份秘密份额分别保存到 student_id_1.txt, student_id_2.txt, student_id_3.txt
# Student_i 获得 student_{j}_{i}.txt
for i in range(1, 4):
    with open(f"student_{id}_{i}.txt", "w") as f:
        f.write(str(shares_y[i - 1]))
    print(f"\n已将份额 student_{id}_{i}.txt 发给 Student_{i}")

print("\n" + "=" * 60)
print(f"  学生 {id} 完成秘密份额分发")
print("=" * 60)