# blockchain

## 如何写一个简单的区块链系统

这是我的区块链课程，每个子文件夹里包含相应的源代码。

本区块链是一个消息区块链，每个区块里包含3个消息。每个消息有消息时间、消息发送者、消息内容、消息接受者、消息hash及消息签名。
每个区块包含区块头和区块体。
区块头里包含区块id、区块引用hash、区块hash、节点公钥及节点签名（对区块id字符串进行签名）
```
pip3 install rsa
```
