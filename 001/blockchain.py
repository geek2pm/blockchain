# -*- coding:utf-8 -*-
import time, datetime
from hashlib import md5
import rsa

#消息
class Message():
    def __init__(self,msg_time,msg_from_pubkey,msg,msg_to_pubkey,msg_hash,msg_sign):
        self.msg_time=msg_time
        self.msg_from_pubkey=msg_from_pubkey
        self.msg=msg
        self.msg_to_pubkey=msg_to_pubkey
        self.msg_hash=msg_hash
        self.msg_sign=msg_sign
    def get_msg_time(self):
        return self.msg_time
    def get_msg_from_pubkey(self):
        return self.msg_from_pubkey
    def get_msg(self):
            return self.msg
    def get_msg_to_pubkey(self):
            return self.msg_to_pubkey   
    def get_msg_hash(self):
            return self.msg_hash
    def get_msg_sign(self):
            return self.msg_sign

#区块头
class Blockhead():
    def __init__(self,block_id,block_ref_hash,block_hash,node_pubkey,node_sign):
        self.block_id=block_id
        self.block_ref_hash=block_ref_hash
        self.block_hash=block_hash
        self.node_pubkey=node_pubkey
        self.node_sign=node_sign
    def get_block_id(self):
        return self.block_id
    def get_block_ref_hash(self):
        return self.block_ref_hash
    def get_block_hash(self):
        return self.block_hash
    def get_node_pubkey(self):
        return self.node_pubkey
    def get_node_sign(self):
        return self.node_sign

#区块体
class Blockbody():
    def __init__(self,msgs):
        self.msgs=msgs #[]
    def get_msg_all(self):
        return self.msgs
    def get_msg_count(self):
        return len(self.msgs)

#区块
class Block():
    def __init__(self,block_head,block_body):
        self.block_head=block_head
        self.block_body=block_body
    def get_head(self):
        return self.block_head
    def get_body(self):
        return self.block_body

#区块链
class Blockchain:
    def __init__(self):
        self.blockchain=[]
        self.name=""
        #可动态配置节点，根据公钥设置是否可信
        self.node_public_keys=[]
    # 设置区块链配置项，以区别其他区块链
    def set_config(self,name,about):
        self.name=name
        self.about=about
        # 根据配置生成区块链创世区块
        block_id = 0
        block_ref_hash = ""
        block_hash = ""
        node_pubkey=""
        node_sign=""
        block_head = Blockhead(block_id,block_ref_hash,block_hash,node_pubkey,node_sign)
        msgs=[]
        msg = Message("msg_time","msg_from_pubkey","msg","msg_to_pubkey","msg_hash","msg_sign")
        msgs.append(msg)
        block_body = Blockbody(msgs)
        block = Block(block_head,block_body)
        self.blockchain.append(block)
        
    def add_block(self,block):
        self.blockchain.append(block)
    def get_all(self):
        return self.blockchain
    def get_last_block(self):
        if len(self.blockchain)>0:
            return False,self.blockchain[len(self.blockchain)-1]
        else:
            return True,None

# 节点

class Node():
    def __init__(self,node_public_key,node_private_key):
        self.node_public_key=node_public_key
        self.node_private_key=node_private_key
        self.blockchain=Blockchain()
        self.blockchain.set_config("blockchain","test")
        self.msgs=[] #临时存储区块的缓存区
        self.msg_count=3 #当数量等于3的时候，写到区块里
        
    def get_blockchain(self):
        return self.blockchain

    def add_msg(self,msg):
        #得到消息后，验证消息。

        m=md5()
        m.update("{}{}{}{}".format(msg.msg_time,msg.msg_from_pubkey,msg.msg,msg.msg_to_pubkey).encode())
        msg_hash=m.hexdigest()

        if msg_hash==msg.msg_hash:
            print("check msg hash ok")
            #验签
            if helper.verify(msg_hash, msg.msg_sign, msg.msg_from_pubkey):
                print("构建区块")
                # block_head
                err,last_block = self.get_blockchain().get_last_block()
                if not err:
                    #消息放在缓存区
                    self.msgs.append(msg)
                    #尝试打包
                    self.mine()  
            else:
                print("不做处理")
        else:
            print("check msg hash err")
    def mine(self):
        # 打包区块
        if len(self.msgs)>=self.msg_count:
            text = ""
            for msg in self.msgs:
                text += "{}{}{}{}".format(msg.msg_time,msg.msg_from_pubkey,msg.msg,msg.msg_to_pubkey)
            #构建区块头
            #对text进行摘要，作为区块体hash
            m=md5()
            m.update(text.encode())
            block_hash=m.hexdigest()
            err,last_block = self.get_blockchain().get_last_block()
            if not err:
                block_id = last_block.get_head().get_block_id()+1
                block_ref_hash = last_block.get_head().get_block_ref_hash()
                #node 节点对 block_id (字符串)进行签名
                node_sign = helper.sign("{}".format(block_id),self.node_private_key)
                block_head = Blockhead(block_id,block_ref_hash,block_hash,self.node_public_key,node_sign)

                #构建区块体
                block_body = Blockbody(self.msgs)

                
                #组装区块
                block = Block(block_head,block_body)
                #添加区块
                self.blockchain.add_block(block)

                #消息缓存清空
                self.msgs=[]
            
            

#操作类
class Helper():
    def __init__(self):
        print("虽然没什么卵用，但还是写上来吧")
    def generate_pub_and_pri_vkey(self):
        public_key, private_key = rsa.newkeys(1024)
        pub_pkcs = public_key.save_pkcs1()
        priv_pkcs = private_key.save_pkcs1()
        return pub_pkcs,priv_pkcs
    #转换
    def pub_pkcs_2_public_key(self,pub_pkcs):
        return rsa.PublicKey.load_pkcs1(pub_pkcs)
    def priv_pkcs_2_private_key(self,priv_pkcs):
        return rsa.PrivateKey.load_pkcs1(priv_pkcs)

    #消息生成
    def make_msg(self,msg_from_pubkey,msg,msg_to_pubkey,msg_from_privkey):
        msg_time = self.get_time()
        m=md5()
        m.update("{}{}{}{}".format(msg_time,msg_from_pubkey,msg,msg_to_pubkey).encode())
        msg_hash=m.hexdigest()
        msg_sign = helper.sign(msg_hash, msg_from_privkey)
        msg = Message(msg_time,msg_from_pubkey,msg,msg_to_pubkey,msg_hash,msg_sign)
        return msg
    #私钥加签
    def sign(self,hashstr,private_key):
        return rsa.sign(hashstr.encode(), private_key, 'SHA-1')
    #公钥验签
    def verify(self,hashstr,signstr,public_key):
        try:
            rsa.verify(hashstr.encode(), signstr, public_key)
            print("验签成功")
            return True
        except:
            print("验签失败")
            return False
    #时间
    def get_time(self):
        return datetime.datetime.now()

helper = Helper()

#节点的公钥和私钥
node_pub_pkcs,node_priv_pkcs = helper.generate_pub_and_pri_vkey()
node_public_key = helper.pub_pkcs_2_public_key(node_pub_pkcs)
node_private_key = helper.priv_pkcs_2_private_key(node_priv_pkcs)

node = Node(node_public_key,node_private_key)
blockchain = node.get_blockchain()

#用户的公钥和私钥
bob_pub_pkcs,bob_priv_pkcs = helper.generate_pub_and_pri_vkey()
bob_public_key = helper.pub_pkcs_2_public_key(bob_pub_pkcs)
bob_private_key = helper.priv_pkcs_2_private_key(bob_priv_pkcs)

alice_pub_pkcs,alice_priv_pkcs = helper.generate_pub_and_pri_vkey()
alice_public_key = helper.pub_pkcs_2_public_key(alice_pub_pkcs)
alice_private_key = helper.priv_pkcs_2_private_key(alice_priv_pkcs)

#用户构建消息
msg1 = helper.make_msg(bob_public_key,"hello",alice_public_key,bob_private_key)
msg2 = helper.make_msg(alice_public_key,"hi",bob_public_key,alice_private_key)
msg3 = helper.make_msg(bob_public_key,"xixi",alice_public_key,bob_private_key)

#消息给节点
node.add_msg(msg1)
node.add_msg(msg2)
node.add_msg(msg3)


#打印区块链

for block in blockchain.get_all():
    block_head = block.get_head()
    block_body = block.get_body()
    
    print("block-{}".format(block_head.get_block_id()))
    print("block_ref_hash:{}".format(block_head.get_block_ref_hash()))
    print("block_hash:{}".format(block_head.get_block_hash()))
    print("node_pubkey:{}".format(block_head.get_node_pubkey()))
    print("node_sign:{}".format(block_head.get_node_sign()))

    nodecheck = False
    
    if helper.verify("{}".format(block_head.get_block_id()),block_head.get_node_sign(),block_head.get_node_pubkey()):
        print("区块记账node节点验签成功")
        nodecheck = True
    else:
        print("区块记账node节点验签失败")

    if nodecheck:
        for msg in block_body.get_msg_all():
            print("msg_time:{}".format(msg.get_msg_time()))
            print("msg_from:{}".format(msg.get_msg_from_pubkey()))
            print("msg:{}".format(msg.get_msg()))
            print("msg_to:{}".format(msg.get_msg_to_pubkey()))
            print("msg_hash:{}".format(msg.get_msg_hash()))
            print("msg_sign:{}".format(msg.get_msg_sign()))
            
            #验证消息是否被篡改
            m=md5()
            m.update("{}{}{}{}".format(msg.msg_time,msg.msg_from_pubkey,msg.msg,msg.msg_to_pubkey).encode())
            msg_hash=m.hexdigest()
            
            if msg_hash==msg.msg_hash:
                #验证消息是否是由msg_from_pubkey发出
                if helper.verify(msg_hash,msg.get_msg_sign(),msg.get_msg_from_pubkey()):
                    print("消息来源正确")

    print("\r\n")
