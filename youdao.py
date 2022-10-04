# -*- coding: utf-8 -*-
from asyncio.log import logger
from distutils.command.config import config
import os
from flask import Flask, request
from gevent.pywsgi import WSGIServer
import re
import uuid
import requests
import hashlib
import time
import yaml
import sys

app = Flask(__name__)

class YouDao:
    def __init__(self, conf) -> None:
        self.YOUDAO_URL = 'https://openapi.youdao.com/api'
        try:
            key = conf["APP_KEY"]
            secret = conf["APP_SECRET"]
            self.verify(key, secret)
            logger.info("ID和密钥校验成功！")
            self.APP_KEY = key
            self.APP_SECRET = secret
        except Exception as e:
            logger.error("Error: {}\n".format(e))
            os.system("PAUSE")
            sys.exit()

    def verify(self, key, secret):
        pattern1 = "^[0-9A-Za-z]{16}$"
        pattern2 = "^[0-9A-Za-z]{32}$"
        if re.match(pattern1, key) == None: raise RuntimeError("应用ID校验失败！请检查ID是否正确设置！")
        if re.match(pattern2, secret) == None: raise RuntimeError("应用密钥校验失败！请检查密钥是否正确设置！")

    def encrypt(self, signStr):
        hash_algorithm = hashlib.sha256()
        hash_algorithm.update(signStr.encode('utf-8'))
        return hash_algorithm.hexdigest()

    def truncate(self, q):
        if q is None:
            return None
        size = len(q)
        return q if size <= 20 else q[0:10] + str(size) + q[size - 10:size]

    def do_request(self, data):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        return requests.post(self.YOUDAO_URL, data=data, headers=headers)

    def decode_text(self, txt):
        chars = "↔◁◀▷▶♤♠♡♥♧♣⊙◈▣◐◑▒▤▥▨▧▦▩♨☏☎☜☞↕↗↙↖↘♩♬㉿㈜㏇™㏂㏘＂＇∼ˇ˘˝¡˚˙˛¿ː∏￦℉€㎕㎖㎗ℓ㎘㎣㎤㎥㎦㎙㎚㎛㎟㎠㎢㏊㎍㏏㎈㎉㏈㎧㎨㎰㎱㎲㎳㎴㎵㎶㎷㎸㎀㎁㎂㎃㎄㎺㎻㎼㎽㎾㎿㎐㎑㎒㎓㎔Ω㏀㏁㎊㎋㎌㏖㏅㎭㎮㎯㏛㎩㎪㎫㎬㏝㏐㏓㏃㏉㏜㏆┒┑┚┙┖┕┎┍┞┟┡┢┦┧┪┭┮┵┶┹┺┽┾╀╁╃╄╅╆╇╈╉╊┱┲ⅰⅱⅲⅳⅴⅵⅶⅷⅸⅹ½⅓⅔¼¾⅛⅜⅝⅞ⁿ₁₂₃₄ŊđĦĲĿŁŒŦħıĳĸŀłœŧŋŉ㉠㉡㉢㉣㉤㉥㉦㉧㉨㉩㉪㉫㉬㉭㉮㉯㉰㉱㉲㉳㉴㉵㉶㉷㉸㉹㉺㉻㈀㈁㈂㈃㈄㈅㈆㈇㈈㈉㈊㈋㈌㈍㈎㈏㈐㈑㈒㈓㈔㈕㈖㈗㈘㈙㈚㈛ⓐⓑⓒⓓⓔⓕⓖⓗⓘⓙⓚⓛⓜⓝⓞⓟⓠⓡⓢⓣⓤⓥⓦⓧⓨⓩ①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⒜⒝⒞⒟⒠⒡⒢⒣⒤⒥⒦⒧⒨⒩⒪⒫⒬⒭⒮⒯⒰⒱⒲⒳⒴⒵⑴⑵⑶⑷⑸⑹⑺⑻⑼⑽⑾⑿⒀⒁⒂"
        for c in chars:
            if c in txt:
                txt = txt.replace(c,"\\u" + str(hex(ord(c)))[2:])
        return txt

    def encode_text(self, txt):
        return re.sub(r'(?i)(?<!\\)(?:\\\\)*\\u([0-9a-f]{4})', lambda m: chr(int(m.group(1), 16)), txt)

    def connect(self, q):
        q = self.decode_text(q)
        data = {}
        data['from'] = 'ja'
        data['to'] = 'zh-CHS'
        data['signType'] = 'v3'
        curtime = str(int(time.time()))
        data['curtime'] = curtime
        salt = str(uuid.uuid1())
        signStr = self.APP_KEY + self.truncate(q) + salt + curtime + self.APP_SECRET
        sign = self.encrypt(signStr)
        data['appKey'] = self.APP_KEY
        data['q'] = q
        data['salt'] = salt
        data['sign'] = sign

        response = self.do_request(data)
        translated = self.encode_text(response.json()["translation"][0])
        return translated

def main():
    http_server = WSGIServer(('0.0.0.0', 21580), app)
    http_server.serve_forever()

@app.route("/")
def home():
    return "youdao Web Wrapper"

@app.route("/translate")
def webtranslate():
    src_text = request.args.get('text')
    return yd_trans.connect(src_text)

def config_loader():
    if not os.path.exists("yd-config.yml"):
        try:
            with open("yd-config.yml",'w',encoding="utf8") as f:
                f.write("APP_KEY: {} # 将x修改为16位的应用ID \nAPP_SECRET: {} # 将x修改为32位应用密钥".format("".join(["x" for _ in range(16)]),"".join(["x" for _ in range(32)])))
            logger.info("配置文件生成成功！请按规则修改配置文件并保存。\n")
            os.system(r"notepad yd-config.yml")
            sys.exit()
        except Exception as e:
            logger.error("配置文件生成失败！错误原因:{}\n".format(e))
            os.system("PAUSE")
            sys.exit()
    try:
        with open("yd-config.yml",'r',encoding='utf8') as f:
            conf = yaml.safe_load(f)
        if conf: logger.info("配置文件加载成功！")
        return conf
    except Exception as e:
        if os.path.exists("yd-config.yml"): os.remove("yd-config.yml")
        logger.error("配置文件加载失败！错误原因:{}\n".format(e))
        os.system("PAUSE")
        sys.exit()

if __name__ == '__main__':
    conf = config_loader()
    yd_trans = YouDao(conf)
    main()