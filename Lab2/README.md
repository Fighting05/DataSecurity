# 实验2：基于电路的零知识证明

**姓名**：郭佳成  **学号**：2311990

## 环境要求

- Python 3.9+
- py-ecc 库

## 安装依赖

```bash
pip install py-ecc
```

或在 conda 环境下：

```bash
conda activate new
pip install py-ecc
```

## 运行方式

```bash
python zk_circuit.py
```

## 程序说明

`zk_circuit.py` 实现了基于 zkSNARK 框架的零知识证明，证明方程 x³+x+5=35 存在解 x=3，且不向验证者透露 x 的值。

程序按以下四个步骤运行：

1. **构建电路**：将方程转化为 R1CS 约束，验证解向量满足所有约束
2. **Setup**：采样 toxic waste τ，生成证明密钥（pk）和验证密钥（vk）
3. **Prove**：证明者用私密 witness 生成哈希承诺和 Fiat-Shamir 响应
4. **Verify**：验证者只用 vk 和公共输入 out=35 验证证明有效性
