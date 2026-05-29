import pymysql
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

local_table = {}
key = get_random_bytes(16)
base_iv = get_random_bytes(16)

def AES_ENC(plaintext, iv):
    # AES加密
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = pad(plaintext, AES.block_size, style='pkcs7')
    ciphertext = aes.encrypt(padded_data)
    return ciphertext

def AES_DEC(ciphertext, iv):
    # AES解密
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = aes.decrypt(ciphertext)
    plaintext = unpad(padded_data, AES.block_size, style='pkcs7')
    return plaintext

def Random_Encrypt(plaintext):
    # 随机生成iv来保证加密结果的随机性
    iv = get_random_bytes(16)
    ciphertext = AES_ENC(iv + AES_ENC(plaintext.encode('utf-8'), iv), base_iv)
    ciphertext = base64.b64encode(ciphertext)
    return ciphertext.decode('utf-8')

def Random_Decrypt(ciphertext):
    plaintext = AES_DEC(base64.b64decode(ciphertext.encode('utf-8')), base_iv)
    plaintext = AES_DEC(plaintext[16:], plaintext[:16])
    return plaintext.decode('utf-8')

def CalPos(plaintext):
    # 插入plaintext，返回对应的Pos
    # 这是FH-OPE频率隐藏的关键：
    # 相同明文多次插入会得到不同的pos（因为使用random.randint）
    # 从而产生不同的密文（隐藏频率）
    presum = sum([v for k, v in local_table.items() if k < plaintext])
    if plaintext in local_table:
        local_table[plaintext] += 1
        # 在[presum, presum + local_table[plaintext] - 1]范围内随机选择一个位置
        # 这保证了相同明文可以插入到不同的随机位置
        return random.randint(presum, presum + local_table[plaintext] - 1)
    else:
        local_table[plaintext] = 1
        return presum

def GetLeftPos(plaintext):
    return sum([v for k, v in local_table.items() if k < plaintext])

def GetRightPos(plaintext):
    return sum([v for k, v in local_table.items() if k <= plaintext])

def Insert(plaintext):
    ciphertext = Random_Encrypt(plaintext)
    # 连接数据库
    conn = pymysql.connect(unix_socket='/var/run/mysqld/mysqld.sock', user='root', password='123456', database='test_db')
    cur = conn.cursor()
    pos = CalPos(plaintext)
    print(f"插入明文: '{plaintext}', 计算位置: {pos}, 密文: {ciphertext[:30]}...")
    cur.execute(f"call pro_insert({pos},'{ciphertext}')")
    conn.commit()
    conn.close()

def Search(left, right):
    # 搜索[left,right]中的信息
    left_pos = GetLeftPos(left)
    right_pos = GetRightPos(right)
    # 连接数据库
    conn = pymysql.connect(unix_socket='/var/run/mysqld/mysqld.sock', user='root', password='123456', database='test_db')
    cur = conn.cursor()
    cur.execute(
        f"select ciphertext from example where encoding >= FHSearch({left_pos}) and encoding < FHSearch({right_pos})")
    rest = cur.fetchall()
    print(f"\n搜索范围: '{left}' ~ '{right}' (位置 {left_pos} ~ {right_pos})")
    print("搜索结果:")
    for x in rest:
        print(f"  密文: {x[0][:30]}... -> 明文: {Random_Decrypt(x[0])}")
    conn.close()

def TestRepeatedInsert():
    """
    测试：不断插入相同数值多次，观察编码树分裂和编码更新
    """
    print("=" * 60)
    print("测试：连续插入相同数值 'apple' 5次")
    print("=" * 60)
    for i in range(5):
        print(f"\n--- 第 {i+1} 次插入 'apple' ---")
        Insert('apple')
    print("\n" + "=" * 60)
    print("测试：连续插入相同数值 'banana' 3次")
    print("=" * 60)
    for i in range(3):
        print(f"\n--- 第 {i+1} 次插入 'banana' ---")
        Insert('banana')

def TestMixedInsert():
    """
    测试：混合插入不同数值
    """
    print("\n" + "=" * 60)
    print("测试：混合插入不同数值")
    print("=" * 60)
    for plaintext in ['apple', 'pear', 'banana', 'orange', 'cherry', 'apple', 'cherry', 'orange']:
        Insert(plaintext)

def ShowLocalTable():
    """
    显示客户端本地表的统计信息
    """
    print("\n" + "=" * 60)
    print("客户端本地表 (local_table) 统计:")
    print("=" * 60)
    for k, v in sorted(local_table.items()):
        print(f"  '{k}': 出现 {v} 次")

if __name__ == '__main__':
    # 先执行重复值测试，观察编码树分裂和编码更新
    TestRepeatedInsert()

    # 再执行混合插入测试
    TestMixedInsert()

    # 显示统计信息
    ShowLocalTable()

    # 假设我们搜索b和p之间的数据
    Search('b', 'p')
