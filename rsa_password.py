# 密码加密
import random
import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5

headers = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Pragma": "no-cache",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
}

def crack_pwd(key: str, hash: str, pwd: str):
#     key = """-----BEGIN PUBLIC KEY-----
# MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDjb4V7EidX/ym28t2ybo0U6t0n
# 6p4ej8VjqKHg100va6jkNbNTrLQqMCQCAYtXMXXp2Fwkk6WR+12N9zknLjf+C9sx
# /+l48mjUU8RqahiFD1XT/u2e0m2EN029OhCgkHx3Fc/KlFSIbak93EH/XlYis0w+
# Xl69GV6klzgxW6d2xQIDAQAB
# -----END PUBLIC KEY-----
# """
    # key的格式
    rsakey = RSA.importKey(key)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)  # 生成对象
    new_pwd = hash + pwd
    cipher_text = base64.b64encode(
        cipher.encrypt(new_pwd.encode("utf-8"))
    )  # 对传递进来的用户名或密码字符串加密
    value = cipher_text.decode('utf8')  # 将加密获取到的bytes类型密文解码成str类型
    return value

# 获取key
def get_act():
    params = {
        "act": "getkey",
        "r": random.random(),
    }
    url = "https://passport.bilibili.com/login"

    response = requests.get(url, headers=headers, params=params)

    # print(response.json())
    hash = response.json()['hash']
    key = response.json()['key']
    # print(hash)
    # print(key)
    return hash, key

hash, key_public_key = get_act()
password = crack_pwd(key_public_key, hash, "qaz123")

# print(hash)
# print(key_public_key)
# print(password)
