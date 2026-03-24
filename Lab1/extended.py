"""
扩展实验：AES对称加密 + Paillier隐私信息获取
"""
from phe import paillier
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64


class AESCipher:
    def __init__(self, key=None):
        self.key = key if key else os.urandom(32)

    def encrypt(self, plaintext):
        data = plaintext.encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        enc = encryptor.update(padded) + encryptor.finalize()
        return base64.b64encode(iv + enc).decode('utf-8')

    def decrypt(self, enc_str):
        data = base64.b64decode(enc_str.encode('utf-8'))
        iv, enc = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(enc) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode('utf-8')


def main():
    print("=" * 60)
    print("  扩展实验：AES + Paillier")
    print("=" * 60)

    # 客户端：生成AES密钥
    aes = AESCipher()
    print("\n[客户端] 生成AES密钥")

    # 原始消息
    messages = ["消息1", "机密数据", "隐私信息", "测试内容"]
    print(f"\n原始消息: {messages}")

    # 客户端：AES加密所有消息
    print("\n[客户端] 用AES加密消息")
    enc_msgs = [aes.encrypt(m) for m in messages]

    # 服务器：存储加密消息
    print("\n[服务器] 存储加密消息")
    server_data = enc_msgs.copy()

    # Paillier密钥生成
    pubkey, privkey = paillier.generate_paillier_keypair()
    print("\n[客户端] 生成Paillier密钥")

    # 客户端选择消息索引
    target_idx = 1
    print(f"\n[客户端] 选择获取第 {target_idx+1} 条消息")

    # 生成密文向量
    vec = []
    for i in range(len(messages)):
        vec.append(pubkey.encrypt(1 if i == target_idx else 0))

    # 服务器：同态计算得到索引
    print("\n[服务器] 同态计算")
    result = None
    for i in range(len(messages)):
        term = vec[i] * (i + 1)
        result = term if result is None else result + term

    # 客户端解密得到索引
    idx = privkey.decrypt(result) - 1
    print(f"\n[客户端] 解密得到索引: {idx}")

    # 获取并解密消息
    final = aes.decrypt(server_data[idx])
    print(f"\n[客户端] AES解密得到: {final}")

    print("\n" + "=" * 60)
    print("  扩展实验完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
