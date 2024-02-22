import copy
import re

import requests
import os
import json
import logging
import login
import brotli

# 配置logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API_URL
RECEIVE_URL = "https://api.bilibili.com/x/vip/privilege/receive"
CHARGING_URL = "https://api.bilibili.com/x/ugcpay/web/v2/trade/elec/pay/quick"

# 必须
UP_MID = os.environ.get("UP_MID")
# 登录的账号列表
PHONE_LIST = os.environ.get("PHONE_LIST")

# 可选
LOGIN_API_URL = os.environ.get("LOGIN_API_URL")
# Z{phone}_USERNAME Z{phone}_PASSWORD
# Z{phone}_COOKIES

HEADERS = {
    'Host': 'api.bilibili.com',
    'Connection': 'keep-alive',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': '*/*',
    'Origin': 'https://account.bilibili.com',
    'Sec-Fetch-Site': 'same-site',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Referer': 'https://account.bilibili.com/',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9',
}

RECEIVE_DATA = {
    'type': '1',
    'platform': 'web',
}

CHARGING_DATA = {
    'bp_num': '5',
    'is_bp_remains_prior': 'true',
    'otype': 'up',
}

# VARIABLE NAME
COOKIE = "Cookie"
CSRF = "csrf"
UPMID = "up_mid"
OID = "oid"
EMPTY_STR = r''
EQUAL = r'='


s = requests.Session()

# 自动登录获取cookie
def get_cookie(username,password):
    # 初始化一个空列表来存放cookies的字典表示
    cookies_list = []

    captcha_key = None
    validation_code = None


    token, validate, challenge = login.start("normal")
    # 获取password加密的key
    hash, key_public_key = login.rsa_password.get_act()
    # 获取加密后的password
    password = login.rsa_password.crack_pwd(key_public_key, hash, password)

    flag, result = login.login(username, password, token, validate, challenge)

    if flag is False:
        # 需要手机验证
        url = result
        flag, result = login.start_sms(url)

        # 结束后重置captcha_key，validation_code防止误触发
        captcha_key = None
        login.reset_validation_code()

    cookies = result
    # 遍历RequestsCookieJar中的每个Cookie对象
    for cookie in cookies:
        cookie_dict = {
            "domain": cookie.domain,
            # "expiry": cookie.expires,  # 注意：不是所有的cookie都有过期时间
            "httpOnly": cookie.has_nonstandard_attr('HttpOnly'),
            "name": cookie.name,
            "path": cookie.path,
            "secure": cookie.secure,
            "value": cookie.value
        }
        # 有的Cookie可能没有'sameSite'属性，这里做个简单的检查
        if cookie.has_nonstandard_attr('SameSite'):
            cookie_dict["sameSite"] = cookie.get_nonstandard_attr('SameSite')
        # 同理，检查并添加'expiry'属性，如果存在的话
        if hasattr(cookie, 'expires') and cookie.expires:
            cookie_dict["expiry"] = cookie.expires
        # 将构造好的字典添加到列表中
        cookies_list.append(cookie_dict)

    # 输出cookie的JSON字典
    result = json.dumps(cookies_list)
    print(result)
    return result


# 获取账号cookies、bili_jct、userid
def load_account_cookies(phone):
    # logger.info("获取每个账号的cookies开始")
    # # 使用split()方法按分号分割字符串，得到一个包含所有账号的列表
    # phones = phone_list.split(';')
    # # 遍历手机号列表，得到cookies列表
    # for phone in phones:

    logger.info(f"获取账号{phone}的Cookies开始")
    # 账号Cookies的变量名
    cookies_var = f"{phone}_COOKIES"
    # 从环境变量中获取cookies（JSON形式字符串，配合登录软件保存的cookies使用，若获取的本来就是普通字符串形式的，则可跳过处理）
    cookies_json = os.environ.get(cookies_var)

    # 如果不手动配置cookies，则每次运行自动登录获取cookies
    if cookies_json is None:
        logger.info(f"未获取到账号{phone}的Cookies，获取账号密码登录")
        # 账号和密码的变量名
        username_var = f"Z{phone}_USERNAME"
        password_var = f"Z{phone}_PASSWORD"
        # 从环境变量中获取username和password
        username = os.environ.get(username_var)
        password = os.environ.get(password_var)
        if username is None or password is None:
            logger.info("账号或密码为空")
        cookies_json = str(get_cookie(username,password))


    # 如果该账号有对应的cookies，则处理并添加到列表中
    if cookies_json:
        try:
            # 解析JSON格式的字符串
            cookies = json.loads(cookies_json)
            # 初始化变量
            cookie_parts = []
            bili_jct = None
            userid = None

            for cookie in cookies:
                # 添加每个cookie的"name=value"表示到列表中
                cookie_parts.append(f"{cookie['name']}={cookie['value']}")
                # 检查name是否是bili_jct，并记录其值
                if cookie['name'] == "bili_jct":
                    logger.info(f"获取到账号{phone}的bili_jct值")
                    bili_jct = cookie['value']
                # 检查name是否是DedeUserID，并记录其值
                if cookie['name'] == "DedeUserID":
                    logger.info(f"获取到账号{phone}的DedeUserID值")
                    userid = cookie['value']

            # 使用.join()方法连接字符串列表，每个部分之间用"; "分隔
            cookie_str = "; ".join(cookie_parts)

            return cookie_str,bili_jct,userid

        except json.JSONDecodeError:
            logger.error(f"账号{phone}的Cookies解析JSON失败")
    else:
        logger.error(f"账号{phone}未找到对应Cookies")


# 领券
def receive_vip_privilege(phone,cookie,bili_jct):
    headers = copy.copy(HEADERS)
    headers.update({COOKIE: cookie})

    data = copy.copy(RECEIVE_DATA)
    data.update({CSRF: bili_jct})

    try:
        logger.info(f"账号{phone}领券开始")
        response = s.post(url=RECEIVE_URL, headers=headers, data=data)
        receive_result = re.findall(r'\{.*?\}', response.text)[0]
        receive_result = json.loads(receive_result)

        # 判断领券成功条件，code为0（message也为0）
        if receive_result["code"] == 0:
            logger.info(f"账号{phone}领券成功")
        else:
            raise RuntimeError(str(receive_result["code"])+receive_result["message"])

    except Exception as e:
        logger.error(f"账号{phone}领券失败: {e}")

# 充电
def trade_elec_pay_quick(phone, cookie, bili_jct, userid):
    headers = copy.copy(HEADERS)
    headers.update({COOKIE: cookie})

    data = copy.copy(CHARGING_DATA)
    data.update({
        UPMID: UP_MID,
        OID: userid,
        CSRF: bili_jct,
    })

    try:
        logger.info(f"账号{phone}充电开始，对象UID{UP_MID}")
        response = s.post(url=CHARGING_URL, headers=headers, data=data)

        # 返回内容有Brotli压缩，要解压，需要安装Brotli库，装了brotli后会自己去解析数据格式，因此代码上不要做任何修改和操作
        # if response.headers.get('Content-Encoding') == 'br':
        #     decompressed_data = brotli.decompress(response.content)
        #     text_data = decompressed_data.decode('utf-8')  # 解压缩后的数据是UTF-8编码的文本
        #     # print(text_data)

        trade_result = re.findall(r'\{.*?\}\}', response.text)[0]
        trade_result = json.loads(trade_result)

        # 判断充电成功条件，code为0且data内msg为None
        if trade_result["code"] == 0 and trade_result["data"]["status"] == 4:
            logger.info(f"账号{phone}充电成功")
        else:
            raise RuntimeError(str(trade_result["code"])+trade_result["data"]["msg"])

    except Exception as e:
        logger.error(f"账号{phone}充电失败: {e}")

if __name__ == "__main__":
    # 使用split()方法按分号分割字符串，得到一个包含所有账号的列表
    phones = PHONE_LIST.split(';')
    # 遍历手机号列表，得到cookies列表
    for phone in phones:
        logger.info("开始处理账号："+phone)
        cookie, bili_jct, userid = load_account_cookies(phone)
        receive_vip_privilege(phone, cookie, bili_jct)
        trade_elec_pay_quick(phone, cookie, bili_jct, userid)