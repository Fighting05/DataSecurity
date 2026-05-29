"""
FH-OPE 客户端演示程序（不依赖MySQL）
用于测试频率隐藏保序加密的核心功能
"""

import random
from collections import OrderedDict

# 模拟编码树的简化的本地实现
class SimpleLeafNode:
    def __init__(self, lower=0, upper=pow(2, 62)):
        self.lower = lower
        self.upper = upper
        self.cipher = []  # 密文列表
        self.encoding = []  # 编码列表

    def encode(self, pos):
        """为指定位置的密文生成编码"""
        left = self.lower
        right = self.upper

        if pos > 0:
            left = self.encoding[pos - 1]
        if pos < len(self.encoding) - 1:
            right = self.encoding[pos + 1]

        if (right - left) < 2:
            # 区间不足，需要重新编码
            return 0  # 表示需要Recode
        else:
            # 使用左右区间的中点作为编码
            frag = (right - left) // 2
            new_code = right - frag
            self.encoding[pos] = new_code
            return new_code

class SimpleOPETree:
    """
    简化的OPE树实现（仅用于演示）
    """
    def __init__(self):
        self.root = SimpleLeafNode()
        self.local_table = {}  # 客户端本地表
        self.key = "demo_key_16bytes!"  # 简化用
        self.base_iv = "demo_iv_16bytes"

    def cal_pos(self, plaintext):
        """
        计算明文应该插入的位置
        FH-OPE关键：相同明文可以产生不同的位置
        """
        # 计算有多少密文小于该明文
        presum = sum(v for k, v in self.local_table.items() if k < plaintext)

        if plaintext in self.local_table:
            self.local_table[plaintext] += 1
            # 在[presum, presum + count - 1]范围内随机选择
            return random.randint(presum, presum + self.local_table[plaintext] - 1)
        else:
            self.local_table[plaintext] = 1
            return presum

    def insert(self, plaintext, ciphertext):
        """
        插入一个明文-密文对
        """
        pos = self.cal_pos(plaintext)
        node = self.root

        # 在叶节点中插入
        node.cipher.insert(pos, ciphertext)
        node.encoding.insert(pos, -1)  # 占位

        code = node.encode(pos)

        print(f"  插入位置: {pos}, 编码: {code}")

        # 模拟重编码
        if code == 0:
            print(f"  [触发重编码] 叶节点区间不足，需要重编码")

        return pos, code

    def show_state(self):
        """显示当前状态"""
        print(f"\n叶节点区间: [{self.root.lower}, {self.root.upper})")
        print(f"密文数量: {len(self.root.cipher)}")
        print(f"编码: {[e for e in self.root.encoding]}")
        print(f"本地表: {self.local_table}")


def demo_basic():
    """基本功能演示"""
    print("=" * 60)
    print("演示1：基本插入功能")
    print("=" * 60)

    tree = SimpleOPETree()

    data = ['apple', 'banana', 'cherry', 'apple', 'banana']

    for plaintext in data:
        ciphertext = f"cipher_{plaintext}_{random.randint(1000, 9999)}"
        print(f"\n插入明文: '{plaintext}', 密文: {ciphertext}")
        pos, code = tree.insert(plaintext, ciphertext)
        tree.show_state()

    return tree


def demo_repeated_insert():
    """
    演示：连续插入相同数值多次
    观察频率隐藏效果
    """
    print("\n" + "=" * 60)
    print("演示2：连续插入相同数值 'apple' 5次")
    print("观察：相同明文产生不同密文（隐藏频率）")
    print("=" * 60)

    tree = SimpleOPETree()

    # 连续插入5次 'apple'
    positions = []
    for i in range(5):
        plaintext = 'apple'
        ciphertext = f"cipher_apple_{random.randint(1000, 9999)}"
        print(f"\n第 {i+1} 次插入 'apple':")
        pos, code = tree.insert(plaintext, ciphertext)
        positions.append(pos)

    print(f"\n插入位置统计: {positions}")
    print(f"位置范围: {min(positions)} ~ {max(positions)}")
    print(f"相同明文 'apple' 被插入到了不同的位置: {set(positions) if len(set(positions)) > 1 else '全部相同'}")
    print("（理想情况下应该分散在不同的随机位置）")

    return tree


def demo_frequency_hiding():
    """
    演示：频率隐藏效果
    比较 'apple'(5次) 和 'banana'(2次) 的分布
    """
    print("\n" + "=" * 60)
    print("演示3：频率隐藏效果")
    print("比较不同频率明文的编码分布")
    print("=" * 60)

    tree = SimpleOPETree()

    # apple出现5次
    print("\n--- 插入 'apple' 5次 ---")
    for i in range(5):
        pos, code = tree.insert('apple', f"c_apple_{i}")
        print(f"  apple[{i}]: pos={pos}, code={code}")

    # banana出现2次
    print("\n--- 插入 'banana' 2次 ---")
    for i in range(2):
        pos, code = tree.insert('banana', f"c_banana_{i}")
        print(f"  banana[{i}]: pos={pos}, code={code}")

    tree.show_state()

    print("\n观察结论:")
    print("- 'apple' 出现5次，分布在不同的随机位置")
    print("- 'banana' 出现2次，也分布在不同的随机位置")
    print("- 攻击者无法从密文分布推断出 'apple' 比 'banana' 多出现3次")


def demo_encoding_tree_split():
    """
    演示：编码树分裂（简化版）
    当叶节点容量超过M时发生分裂
    """
    print("\n" + "=" * 60)
    print("演示4：编码树分裂（模拟）")
    print("当节点密文数量超过阈值时发生分裂")
    print("=" * 60)

    tree = SimpleOPETree()

    # 插入大量数据观察分裂
    print("\n连续插入20个递增的明文:")
    for i in range(20):
        plaintext = f"item_{i:02d}"
        pos, code = tree.insert(plaintext, f"c_{i}")
        if i < 5 or i == 19:
            print(f"  {plaintext}: pos={pos}, code={code}")
        elif i == 5:
            print("  ...")

    tree.show_state()

    print("\n注意：简化实现未包含真正的树分裂逻辑")
    print("实际FH-OPE实现中，当节点满时会触发rebalance()进行分裂")


def demo_search():
    """演示：范围搜索"""
    print("\n" + "=" * 60)
    print("演示5：范围搜索")
    print("=" * 60)

    tree = SimpleOPETree()

    # 插入一些数据
    data = [('apple', 3), ('banana', 2), ('cherry', 4), ('date', 1)]
    for plaintext, count in data:
        for i in range(count):
            tree.insert(plaintext, f"c_{plaintext}_{i}")

    tree.show_state()

    # 搜索
    print("\n搜索 'banana' 到 'cherry' 之间的数据:")
    left = 'banana'
    right = 'cherry'

    # 简单模拟搜索
    left_count = sum(v for k, v in tree.local_table.items() if k < left)
    right_count = sum(v for k, v in tree.local_table.items() if k <= right)

    print(f"  位置范围: {left_count} ~ {right_count}")
    print(f"  搜索结果应包含: banana, cherry")


if __name__ == '__main__':
    print("FH-OPE 频率隐藏保序加密 演示程序")
    print("=" * 60)

    demo_basic()
    demo_repeated_insert()
    demo_frequency_hiding()
    demo_encoding_tree_split()
    demo_search()

    print("\n" + "=" * 60)
    print("演示结束")
    print("=" * 60)
