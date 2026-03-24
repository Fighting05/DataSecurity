from phe import paillier


def main():
    print("=" * 60)
    print("          基于Paillier算法的隐私信息获取实验")
    print("=" * 60)

    # ====== 服务器初始化 ======
    print("\n【服务器端初始化】")
    print("-" * 60)

    # 服务器持有m个消息
    server_messages = [
        "Hello, World!",
        "数据安全实验",
        "Paillier同态加密",
        "隐私信息获取",
        "1-out-of-N不经意传输"
    ]
    m = len(server_messages)

    # ====== 客户端：密钥生成 ======
    print("\n【客户端：密钥生成】")
    print("-" * 60)
    print("正在生成Paillier密钥对...")
    public_key, private_key = paillier.generate_paillier_keypair()
    print("✓ 密钥生成完成")
    print(f"  公钥 n = {public_key.n}")

    # 客户端将公钥发送给服务器（模拟）
    print("\n客户端 → 服务器：发送公钥")

    # ====== 客户端：选择要获取的消息 ======
    print("\n【客户端：选择消息】")
    print("-" * 60)

    target_index = 2  # 获取第3条消息（索引从0开始）
    print(f"客户端选择获取第 {target_index+1} 条消息")

    # 生成密文向量：enc(0) 和 enc(1)
    print("\n正在生成密文向量...")
    encrypted_vector = []
    for i in range(m):
        if i == target_index:
            encrypted_vector.append(public_key.encrypt(1))
        else:
            encrypted_vector.append(public_key.encrypt(0))

    # 客户端将密文向量发送给服务器（模拟）
    print("\n客户端 → 服务器：发送密文向量")

    # ====== 服务器：计算响应 ======
    print("\n【服务器：计算响应】")
    print("-" * 60)
    print("服务器接收到密文向量，正在进行同态计算...")

    # 消息转整数的函数
    def message_to_int(msg):
        return sum(ord(c) for c in msg)

    def int_to_message(value, original_messages):
        for msg in original_messages:
            if message_to_int(msg) == value:
                return msg
        return None

    # 服务器端同态计算：C = v1 * p1 + v2 * p2 + ... + vm * pm
    result = None
    for i in range(m):
        msg_int = message_to_int(server_messages[i])
        # 数乘同态：v_i * p_i
        term = encrypted_vector[i] * msg_int
        if result is None:
            result = term
        else:
            # 加法同态：累加
            result = result + term

    print("✓ 同态计算完成")
    print("\n服务器 → 客户端：发送计算结果")

    # ====== 客户端：解密 ======
    print("\n【客户端：解密结果】")
    print("-" * 60)
    print("客户端接收到响应，正在解密...")
    decrypted_int = private_key.decrypt(result)
    print(f"✓ 解密得到整数: {decrypted_int}")

    # 还原消息
    decrypted_message = int_to_message(decrypted_int, server_messages)
    print(f"✓ 还原得到消息: {decrypted_message}")

    # 验证正确性
    print("\n" + "=" * 60)
    print("【实验结果验证】")
    print("=" * 60)
    expected_message = server_messages[target_index]
    if decrypted_message == expected_message:
        print(f"✓ 成功！正确获取到消息: {decrypted_message}")
        print(f"✓ 服务器无法知道客户端选择了第 {target_index+1} 条消息")
        print("\n实验完成！")
    else:
        print(f"✗ 失败！期望: {expected_message}, 实际: {decrypted_message}")
    print("=" * 60)


def test_multiple_indices():
    """测试获取不同索引的消息"""
    print("\n" + "=" * 60)
    print("          测试获取不同索引的消息")
    print("=" * 60)

    server_messages = ["消息1", "消息2", "消息3", "消息4", "消息5"]
    m = len(server_messages)

    def message_to_int(msg):
        return sum(ord(c) for c in msg)

    def int_to_message(value, original_messages):
        for msg in original_messages:
            if message_to_int(msg) == value:
                return msg
        return None

    public_key, private_key = paillier.generate_paillier_keypair()

    for test_idx in range(m):
        print(f"\n测试获取第 {test_idx+1} 条消息...")

        # 生成密文向量
        encrypted_vector = []
        for i in range(m):
            if i == test_idx:
                encrypted_vector.append(public_key.encrypt(1))
            else:
                encrypted_vector.append(public_key.encrypt(0))

        # 服务器计算
        result = None
        for i in range(m):
            msg_int = message_to_int(server_messages[i])
            term = encrypted_vector[i] * msg_int
            if result is None:
                result = term
            else:
                result = result + term

        # 解密
        decrypted_int = private_key.decrypt(result)
        decrypted_message = int_to_message(decrypted_int, server_messages)

        expected = server_messages[test_idx]
        if decrypted_message == expected:
            print(f"  ✓ 成功: {decrypted_message}")
        else:
            print(f"  ✗ 失败: 期望 {expected}, 实际 {decrypted_message}")


if __name__ == "__main__":
    main()

    # 取消下面的注释来测试获取不同索引的消息
    # test_multiple_indices()
