import copy
import json
import os
import re
import time
import requests
from loguru import logger
import rsa_password

HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Pragma": "no-cache",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
}

# 必须
API_URL = os.environ.get("LOGIN_API_URL")
# 可选
OCR_URL = os.environ.get("OCR_URL")
OCR_TOKEN = os.environ.get("OCR_TOKEN")

# 会话保持
session = requests.session()


# 注册点字
def register_click():
    url = "https://passport.bilibili.com/x/passport-login/captcha"
    params = {
        "t": int(time.time() * 1000),
    }
    headers = copy.copy(HEADERS)
    response = requests.get(url, headers=headers, params=params)
    challenge = response.json()["data"]["geetest"]["challenge"]
    gt = response.json()["data"]["geetest"]["gt"]
    token = response.json()["data"]["token"]
    # print('第一次请求：========>','challenge:',challenge,'gt:',gt)
    logger.info(f'获取验证码gt:{gt},challenge:{challenge},token:{token}')
    return token, gt, challenge


# 注册验证码的点字
def register_sms_click():
    url = "https://passport.bilibili.com/x/safecenter/captcha/pre"
    params = {
        "source": "risk",
    }
    headers = copy.copy(HEADERS)
    response = requests.post(url, headers=headers, data=params)
    gee_challenge = response.json()["data"]["gee_challenge"]
    gee_gt = response.json()["data"]["gee_gt"]
    recaptcha_token = response.json()["data"]["recaptcha_token"]

    logger.info(f'获取验证码gee_gt:{gee_gt},gee_challenge:{gee_challenge},token:{recaptcha_token}')
    return recaptcha_token, gee_gt, gee_challenge


# 过验证码
def get_validate(gt,challenge,ocr_url,ocr_token):
    api_url = API_URL+"/click"
    params = {
        "gt": gt,
        "challenge": challenge,
        "ocr_url": ocr_url,
        "token": ocr_token,
    }

    try:
        res = requests.get(api_url, params=params).json()['data']
        result = json.loads(res)['result']
        score = json.loads(res)['score']
        validate = json.loads(res)['validate']
        gt = json.loads(res)['gt']
        challenge = json.loads(res)['challenge']

        #print(result,score,validate,gt,challenge)
        return result,score,validate,gt,challenge
    except:
        return None, None, None, None, None


# 开始验证
def start(model):
    ocr_url = OCR_URL
    ocr_token = OCR_TOKEN

    while True:
        # 根据模式获取的challenge不同
        if model == "sms":
            token, gt, challenge = register_sms_click()
        elif model == "normal":
            token, gt, challenge = register_click()
        else:
            token, gt, challenge = register_click()

        result,score,validate,gt,challenge = get_validate(gt,challenge,ocr_url,ocr_token)
        if result == "success":
            logger.success(f'点字验证成功========>result:{result},score:{score},validate:{validate},gt:{gt},challenge:{challenge},token:{token}')
            return token,validate,challenge
        else:
            logger.error(f'点字验证失败，重新验证')


# 登录
def login(username,password,token,validate,challenge):
    url = "https://passport.bilibili.com/x/passport-login/web/login"
    params = {
        "source": "main_web",
        "username": username,
        "password": password,
        "go_url": '',
        "token": token,
        "validate": validate,
        "seccode": validate+"|jordan",
        "challenge": challenge,
    }
    headers = copy.copy(HEADERS)
    response = session.post(url, headers=headers, data=params)
    resp = response.json()['data']

    # print(response.text)
    # 获取cookie
    # print(response.cookies)

    # 检查是否需要手机验证
    status = resp['status']
    if status != 0:
        logger.error(resp['message']+resp['url'])
        return False, resp['url']
    else:
        # logger.success(f'{username}的cookie:{response.cookies}')
        logger.success(f'成功获取{username}的cookie')
        return True, response.cookies


# 发送短信验证码
def send_sms(tmp_code,token,validate,challenge):
    url = "https://passport.bilibili.com/x/safecenter/common/sms/send"
    params = {
        "tmp_code": tmp_code,
        "sms_type": "loginTelCheck",
        "recaptcha_token": token,
        "gee_challenge": challenge,
        "gee_seccode": validate + "|jordan",
        "gee_validate": validate,
    }
    headers = copy.copy(HEADERS)
    response = session.post(url, headers=headers, data=params)
    resp = response.json()
    if resp['code'] == 0:
        captcha_key = resp['data']['captcha_key']
        logger.success(f'sms发送成功captcha_key:{captcha_key}')
        return captcha_key
    else:
        logger.error(response.text)
        return None


# 获取短信验证码
def get_validation_code():
    url = API_URL+"/get_validation_code"
    response = requests.get(url).json()
    validation_code = response['validation_code']
    return validation_code


# 验证短信验证码
def verify_sms(tmp_code,captcha_key,validation_code,request_id):
    url = "https://passport.bilibili.com/x/safecenter/login/tel/verify"
    params = {
        "tmp_code": tmp_code,
        "captcha_key": captcha_key,
        "type": "loginTelCheck",
        "code": validation_code,
        "request_id": request_id,
        "source": "risk",
    }
    headers = copy.copy(HEADERS)
    response = session.post(url, headers=headers, data=params).json()
    if response['code'] == 0:
        code = response['data']['code']
        logger.success(f'sms验证成功code:{code}')
        return code
    else:
        message = response['message']
        logger.error(f'sms验证失败message:{message}')
        return None


# 进行验证码登录
def exchange_cookies(code):
    url = "https://passport.bilibili.com/x/passport-login/web/exchange_cookie"
    params = {
        "source": "risk",
        "code": code
    }
    headers = copy.copy(HEADERS)
    response = session.post(url, headers=headers, data=params)

    # logger.success(f'{username}的cookie:{response.cookies}')
    logger.success(f'成功获取cookie')
    falg = True
    return falg, response.cookies


# 结束后重置验证码，防止干扰
def reset_validation_code():
    url = API_URL+"/reset_validation_code"
    response = requests.get(url)
    return True


# 等待验证码
def wait_validation_code(url):
    clock = 0
    while True:
        validation_code = get_validation_code()
        if validation_code is not None:
            break
        time.sleep(1)
        clock += 1
        if clock > 60:
            logger.error(f'获取验证码超时，重新获取')
            return None
    return validation_code


# 手机验证
def start_sms(url):
    while True:
        # 重置validation_code防止干扰
        reset_validation_code()
        # 使用正则表达式提取tmp_token和request_id
        tmp_code = re.search(r'tmp_token=([^&]+)', url).group(1)
        request_id = re.search(r'request_id=([^&]+)', url).group(1)

        token, validate, challenge = start("sms")
        # 发送验证码
        captcha_key = send_sms(tmp_code, token, validate, challenge)

        # 等待验证码
        validation_code = wait_validation_code(url)
        # 如果验证码为None代表超时,重新获取，否则跳出循环
        if validation_code is not None:
            break

    # 验证验证码
    code = verify_sms(tmp_code, captcha_key, validation_code, request_id)
    if code is not None:
        # 登录，获取cookies
        falg, result = exchange_cookies(code)
        return falg, result
    else:
        start_sms(url)
