"""
\tUPI 支付指令链接提取脚本。

说明：
- UPI 成功后会返回 Stripe 的支付指令链接。
- 本脚本只输出 `payments.stripe.com/upi/instructions/` 最终链接或其上游跳转链接。
- 默认只读取当前项目的 proxy_seeds.txt。

用法：
  1) 环境变量方式：
     UPI_TOKEN="..." python upi_extract.py

  2) 文件方式：
     把 token 放到当前目录 token.txt
     python upi_extract.py

常用环境变量：
  UPI_CONFIRM_INLINE_PM=0   # 默认按 gpthel 流程：先创建 PM，再 confirm 引用 PM
  UPI_UPDATE_TAX_REGION=1   # IN UPI 流程同步 ChatGPT/Stripe 税务地区
  UPI_BOOTSTRAP_COUNTRY=IN  # Checkout / 首次 Stripe init 地区
  UPI_PROMOTION_COUNTRY=IN  # checkout/update 地区；默认与 UPI 主链路保持 IN/IN/IN
  UPI_PROVIDER_COUNTRY=IN   # Stripe refresh / 税务 / PM / approve 地区
  # 兼容 OpenAI oaics_*/open_ai 自定义 Checkout：自动切换 Elements→PM→
  # ConfirmationToken→checkout/confirm→PI/SI confirm 链路；正价可出 instructions 链
  UPI_MAX_RETRY=5
  UPI_ROTATE_FINGERPRINT_ON_RETRY=1 # 第一次使用账号固定指纹，重试时切换新指纹/设备会话
  UPI_RISK_CONTROL_MAX=2  # 同一任务连续命中上游风控后停止继续建 checkout
  UPI_PROVIDER_PER_CHECKOUT=1
  UPI_MAX_APPROVE_BLOCKED=5 # 兼容旧配置；明确 blocked 现立即停止，不继续提交审批
  UPI_APPROVE_CYCLES=5      # approve 轮数；每轮重建会话并重新 mint sentinel token
  UPI_APPROVE_ATTEMPTS_PER_CYCLE=2 # 每轮 approve 次数
  UPI_APPROVE_CONFIRM_FIRST=auto # auto=仅内部 Checkout(oaics_) 先试 /checkout/confirm；1=总是；0=关闭
  # approve 返回 blocked/expired/exception 或 HTTP 401/403/429 均立即停止当前 Checkout
  UPI_POLL_TIMEOUT=100      # payment_pages 轮询窗口（秒）
  UPI_WORKERS=1
  UPI_WORKERS_MAX=1
  UPI_APPROVE_RETRY_MAX=10 # approve 阶段复用当前 provider 代理重试
  UPI_APPROVE_STICKY=1     # approve 优先历史/当前出口，失败后切下一个 provider 出口
  UPI_FOLLOW_REDIRECT=1
  UPI_REQUIRE_ZERO=1        # 默认强制 0 元，不生成非 0 元链；用户选择「原价链」时为 0
UPI_ORIGINAL_PRICE_ZERO_FALLBACK=0  # 原价链被上游压成 0 元时是否降级交付 0 元链
  UPI_ORIGINAL_PRICE_SKIP_PROMO=1 # 原价链时跳过优惠 checkout/update，稳定保留正价金额
  UPI_DUMP_LIMIT=6000       # 抓包响应保存长度
  UPI_PROXY_SKIP_FAILED=1   # 普通流程失败下次软跳过
  UPI_PROXY_REMOVE_FAILED=1 # 明确的代理失败会从 proxy_seeds.txt 移除
  UPI_PROXY_DEFAULT_SCHEME=http # 裸代理默认协议；Mars SOCKS5 可设 socks5h
  UPI_PROXY_FAIL_COOLDOWN=180 # 失败代理冷却秒数，0 表示按旧逻辑一直跳过
  UPI_PROXY_REMOVE_AFTER_FAILS=3 # 已复用代理健康类失败累计 3 次移除；普通代理失败 1 次移除
  UPI_PROXY_LEASE=1         # 跨进程租约，避免并发任务同时使用同一 sticky Seed
  UPI_PROXY_LEASE_TTL=900   # 租约过期秒数；异常退出后自动回收
  UPI_PROXY_LEASE_WAIT=0    # 获取已占用 Seed 时等待秒数，0 表示立即尝试下一条
  UPI_ZERO_CACHE=1          # 记录 checkout 的 0 元观察结果，供日志和排查使用
  UPI_ZERO_CACHE_SCHEDULING=0 # 显式设为 1 才按 0 元观察结果筛选/优先调度
  UPI_BROWSER_MODE=headless  # UPI 严格使用真实 Playwright 无头 Chromium，不回退 HTTP 模拟
  UPI_BROWSER_EXECUTABLE_PATH= # 可选：指定 Chrome/Chromium 可执行文件
  UPI_DIVERSE_FINGERPRINTS=1  # 新账号 sticky 指纹默认抽取 Chrome/Edge/Firefox + Windows/macOS
  UPI_FORCE_CHROME_PROFILE=0  # 兼容旧版：显式设为 1 才强制覆盖为 Chrome/Windows/hi-IN
  UPI_OFFICIAL_CHECKOUT_FALLBACK=1
  UPI_OFFICIAL_CHECKOUT_TIMEOUT=45
  PP_PROMO_MODE=campaign      # 默认直接走 promo_campaign，避免 coupon 再 fallback 多耗时
  PP_TRIAL_DAYS=30            # 仅 PP_PROMO_MODE=trial/free_trial 时使用
"""

from __future__ import annotations

import json
import math
import base64
import hashlib
import os
import random
import re
import secrets
import sys
import time
import uuid
from contextlib import contextmanager
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, RLock, Thread, local
from typing import Any, Callable
from urllib.parse import parse_qsl, quote, urlencode, unquote, urljoin, urlparse, urlsplit, urlunsplit

import requests

try:
    from ...upi_browser_transport import (
        PlaywrightBrowserSession,
        ProtocolHttpSession,
        UPI_HEADLESS_BROWSER_LAUNCH_FAILED,
        UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED,
        UPI_HEADLESS_BROWSER_REQUEST_FAILED,
        UPI_HEADLESS_BROWSER_UNAVAILABLE,
    )
except ImportError:  # pragma: no cover - direct CLI fallback
    project_root = Path(__file__).resolve().parents[3]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from standalone_core.upi_browser_transport import (  # type: ignore
        PlaywrightBrowserSession,
        ProtocolHttpSession,
        UPI_HEADLESS_BROWSER_LAUNCH_FAILED,
        UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED,
        UPI_HEADLESS_BROWSER_REQUEST_FAILED,
        UPI_HEADLESS_BROWSER_UNAVAILABLE,
    )


SCRIPT_DIR = Path(__file__).resolve().parent
_runtime_dir = os.environ.get("UPI_RUNTIME_DIR", "").strip()
RUNTIME_DIR = Path(_runtime_dir).expanduser() if _runtime_dir else SCRIPT_DIR
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR = RUNTIME_DIR / "logs"
DUMP_DIR = RUNTIME_DIR / "dumps"
LOG_DIR.mkdir(parents=True, exist_ok=True)
DUMP_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_TIMEOUT = 30
CHATGPT_TIMEOUT = 45
UPI_UNAVAILABLE_ERROR = "当前账号支付方式不支持 UPI"
UPI_METHOD_UNAVAILABLE_ERROR = "UPI_METHOD_UNAVAILABLE"
UPI_AMOUNT_UNKNOWN_ERROR = "UPI_AMOUNT_UNKNOWN"
UPI_AMOUNT_NONZERO_ERROR = "UPI_AMOUNT_NONZERO"
UPI_RISK_CONTROL_REPEATED_ERROR = "UPI_RISK_CONTROL_REPEATED"
UPI_OFFICIAL_CHECKOUT_CAPTURE_FAILED = "UPI_OFFICIAL_CHECKOUT_CAPTURE_FAILED"
UPI_OFFICIAL_CHECKOUT_QR_NOT_FOUND = "UPI_OFFICIAL_CHECKOUT_QR_NOT_FOUND"
UPI_OFFICIAL_CHECKOUT_CAPTCHA = "UPI_OFFICIAL_CHECKOUT_CAPTCHA"
UPI_ORIGINAL_PRICE_APPROVAL_REQUIRED = "UPI_ORIGINAL_PRICE_APPROVAL_REQUIRED"
UPI_OAICS_ZERO_DECLINED = "UPI_OAICS_ZERO_DECLINED"
UPI_ZERO_INELIGIBLE = "UPI_ZERO_INELIGIBLE"
UPI_ACCOUNT_AUTH_EXPIRED = "UPI_ACCOUNT_AUTH_EXPIRED"
STRIPE_VERSION_FULL = (
    "2025-03-31.basil; checkout_server_update_beta=v1; "
    "checkout_manual_approval_preview=v1"
)
DEFAULT_STRIPE_RUNTIME_VERSION = "6f8494a281"
CHATGPT_CLIENT_VERSION = "prod-8b282ae6b2e95fa180d7bde7b664e1446691fac0"
CHATGPT_CLIENT_BUILD_NUMBER = "10379027"
DEFAULT_STRIPE_PK = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
)
def configured_country(name: str, default: str) -> str:
    value = str(os.environ.get(name, default) or default).strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", value):
        raise RuntimeError(f"{name} 必须是两位国家代码")
    return value


def configured_countries(name: str, default: str) -> list[str]:
    value = str(os.environ.get(name, default) or default)
    countries = [part.strip().upper() for part in value.split(",")]
    if not countries or any(not re.fullmatch(r"[A-Z]{2}", country) for country in countries):
        raise RuntimeError(f"{name} 必须是以逗号分隔的两位国家代码")
    return countries


UPI_BOOTSTRAP_COUNTRY = configured_country(
    "UPI_BOOTSTRAP_COUNTRY", os.environ.get("UPI_CHECKOUT_COUNTRY", "IN")
)
UPI_PROMOTION_COUNTRIES = configured_countries("UPI_PROMOTION_COUNTRY", "IN")
UPI_PROMOTION_COUNTRY = UPI_PROMOTION_COUNTRIES[0]
UPI_PROVIDER_COUNTRY = configured_country(
    "UPI_PROVIDER_COUNTRY", os.environ.get("UPI_BILLING_COUNTRY", "IN")
)

COUNTRY_CURRENCY = {
    "BR": "BRL",
    "NL": "EUR",
    "BE": "EUR",
    "DE": "EUR",
    "FR": "EUR",
    "US": "USD",
    "IN": "INR",
    "JP": "JPY",
    "VN": "VND",
}

DEFAULT_UPI_BILLING = {
    "email": "redacted@example.invalid",
    "name": "Aisha Sharma",
    "country": "IN",
    "line1": "24 Park Street",
    "line2": "",
    "city": "Kolkata",
    "postal_code": "700016",
    "state": "WB",
}

IN_BILLING_NAMES = [
    ("Aisha", "Sharma"),
    ("Arjun", "Mehta"),
    ("Kavya", "Gupta"),
    ("Rohan", "Kapoor"),
    ("Priya", "Nair"),
    ("Aditi", "Rao"),
    ("Vikram", "Singh"),
    ("Sneha", "Kulkarni"),
    ("Rahul", "Patel"),
    ("Ananya", "Iyer"),
    ("Kabir", "Khan"),
    ("Meera", "Joshi"),
    ("Dev", "Menon"),
    ("Sanya", "Malhotra"),
    ("Ishaan", "Chawla"),
    ("Riya", "Bose"),
    ("Aditya", "Deshmukh"),
    ("Nisha", "Pillai"),
    ("Karan", "Bhalla"),
    ("Tara", "Sundaram"),
    ("Vivaan", "Reddy"),
    ("Mira", "Fernandes"),
    ("Aarav", "Nair"),
    ("Diya", "Agarwal"),
    ("Zoya", "Kaul"),
    ("Neha", "Verma"),
    ("Siddharth", "Rao"),
    ("Pooja", "Shah"),
    ("Manish", "Tiwari"),
    ("Divya", "Menon"),
    ("Akash", "Bhatia"),
    ("Ritu", "Chauhan"),
    ("Harsh", "Vardhan"),
    ("Shreya", "Banerjee"),
    ("Nikhil", "Saxena"),
    ("Anjali", "Deshpande"),
    ("Rakesh", "Yadav"),
    ("Deepika", "Ranganathan"),
    ("Varun", "Shetty"),
    ("Ishita", "Mukherjee"),
    ("Sahil", "Dutta"),
    ("Preeti", "Krishnan"),
    ("Aman", "Bhatt"),
    ("Swati", "Kelkar"),
    ("Faizan", "Ahmed"),
    ("Trisha", "Sen"),
    ("Yash", "Thakur"),
]

# Devanagari rendering of the same names; used when the admin picks the
# Hindi billing script so the filled-in address matches an Indian user.
IN_BILLING_NAMES_HI = {
    ("Aisha", "Sharma"): ("आयशा", "शर्मा"),
    ("Arjun", "Mehta"): ("अर्जुन", "मेहता"),
    ("Kavya", "Gupta"): ("काव्या", "गुप्ता"),
    ("Rohan", "Kapoor"): ("रोहन", "कपूर"),
    ("Priya", "Nair"): ("प्रिया", "नायर"),
    ("Aditi", "Rao"): ("अदिति", "राव"),
    ("Vikram", "Singh"): ("विक्रम", "सिंह"),
    ("Sneha", "Kulkarni"): ("स्नेहा", "कुलकर्णी"),
    ("Rahul", "Patel"): ("राहुल", "पटेल"),
    ("Ananya", "Iyer"): ("अनन्या", "अय्यर"),
    ("Kabir", "Khan"): ("कबीर", "खान"),
    ("Meera", "Joshi"): ("मीरा", "जोशी"),
    ("Dev", "Menon"): ("देव", "मेनन"),
    ("Sanya", "Malhotra"): ("सान्या", "मल्होत्रा"),
    ("Ishaan", "Chawla"): ("ईशान", "चावला"),
    ("Riya", "Bose"): ("रिया", "बोस"),
    ("Aditya", "Deshmukh"): ("आदित्य", "देशमुख"),
    ("Nisha", "Pillai"): ("निशा", "पिल्लई"),
    ("Karan", "Bhalla"): ("करण", "भल्ला"),
    ("Tara", "Sundaram"): ("तारा", "सुंदरम"),
    ("Vivaan", "Reddy"): ("विवान", "रेड्डी"),
    ("Mira", "Fernandes"): ("मीरा", "फर्नांडीस"),
    ("Aarav", "Nair"): ("आरव", "नायर"),
    ("Diya", "Agarwal"): ("दिया", "अग्रवाल"),
    ("Zoya", "Kaul"): ("ज़ोया", "कौल"),
    ("Neha", "Verma"): ("नेहा", "वर्मा"),
    ("Siddharth", "Rao"): ("सिद्धार्थ", "राव"),
    ("Pooja", "Shah"): ("पूजा", "शाह"),
    ("Manish", "Tiwari"): ("मनीष", "तिवारी"),
    ("Divya", "Menon"): ("दिव्या", "मेनन"),
    ("Akash", "Bhatia"): ("आकाश", "भाटिया"),
    ("Ritu", "Chauhan"): ("ऋतु", "चौहान"),
    ("Harsh", "Vardhan"): ("हर्ष", "वर्धन"),
    ("Shreya", "Banerjee"): ("श्रेया", "बनर्जी"),
    ("Nikhil", "Saxena"): ("निखिल", "सक्सेना"),
    ("Anjali", "Deshpande"): ("अंजलि", "देशपांडे"),
    ("Rakesh", "Yadav"): ("राकेश", "यादव"),
    ("Deepika", "Ranganathan"): ("दीपिका", "रंगनाथन"),
    ("Varun", "Shetty"): ("वरुण", "शेट्टी"),
    ("Ishita", "Mukherjee"): ("इशिता", "मुखर्जी"),
    ("Sahil", "Dutta"): ("साहिल", "दत्ता"),
    ("Preeti", "Krishnan"): ("प्रीति", "कृष्णन"),
    ("Aman", "Bhatt"): ("अमन", "भट्ट"),
    ("Swati", "Kelkar"): ("स्वाति", "केलकर"),
    ("Faizan", "Ahmed"): ("फैज़ान", "अहमद"),
    ("Trisha", "Sen"): ("तृषा", "सेन"),
    ("Yash", "Thakur"): ("यश", "ठाकुर"),
}

IN_BILLING_CITIES_HI = {
    "Kolkata": "कोलकाता",
    "Bengaluru": "बेंगलुरु",
    "Mumbai": "मुंबई",
    "New Delhi": "नई दिल्ली",
    "Chennai": "चेन्नई",
    "Hyderabad": "हैदराबाद",
    "Pune": "पुणे",
    "Ahmedabad": "अहमदाबाद",
    "Jaipur": "जयपुर",
    "Lucknow": "लखनऊ",
    "Kochi": "कोच्चि",
    "Chandigarh": "चंडीगढ़",
}

# street/city/postal/state. Kolkata/Bengaluru/Mumbai/Delhi keep the
# original entries so existing accounts that already used them stay sane.
IN_BILLING_ADDRESSES = [
    ("24 Park Street", "Kolkata", "700016", "WB"),
    ("14 MG Road", "Bengaluru", "560001", "KA"),
    ("18 Marine Drive", "Mumbai", "400020", "MH"),
    ("32 Connaught Place", "New Delhi", "110001", "DL"),
    ("1B Rasheed Place", "Kolkata", "700019", "WB"),
    ("56 Elgin Road", "Kolkata", "700020", "WB"),
    ("8A Gokhale Road", "Kolkata", "700052", "WB"),
    ("77 Residency Road", "Bengaluru", "560025", "KA"),
    ("Indiranagar 100 Feet Road", "Bengaluru", "560038", "KA"),
    ("12 Brigade Road", "Bengaluru", "560001", "KA"),
    ("304 Linking Road", "Mumbai", "400052", "MH"),
    ("77 Hill Road", "Mumbai", "400050", "MH"),
    ("22 Carter Road", "Mumbai", "400050", "MH"),
    ("115 Janpath", "New Delhi", "110001", "DL"),
    ("9 Green Park", "New Delhi", "110016", "DL"),
    ("27 Greater Kailash", "New Delhi", "110048", "DL"),
    ("41 Anna Salai", "Chennai", "600002", "TN"),
    ("33 Cathedral Road", "Chennai", "600086", "TN"),
    ("19 Nungambakkam High Road", "Chennai", "600034", "TN"),
    ("55 Jubilee Hills Road", "Hyderabad", "500033", "TS"),
    ("28 Banjara Hills Road", "Hyderabad", "500034", "TS"),
    ("22 Srinagar Colony Main Road", "Hyderabad", "500073", "TS"),
    ("26 Gachibowli Main Road", "Hyderabad", "500032", "TS"),
    ("88 FC Road", "Pune", "411005", "MH"),
    ("23 Law College Road", "Pune", "411004", "MH"),
    ("15 Aundh Road", "Pune", "411007", "MH"),
    ("39 Viman Nagar Road", "Pune", "411014", "MH"),
    ("21 Koregaon Park Road", "Pune", "411001", "MH"),
    ("63 Aundh Baner Road", "Pune", "411045", "MH"),
    ("31 CG Road", "Ahmedabad", "380009", "GJ"),
    ("67 Ashram Road", "Ahmedabad", "380009", "GJ"),
    ("17 Satellite Road", "Ahmedabad", "380015", "GJ"),
    ("44 MI Road", "Jaipur", "302001", "RJ"),
    ("12 Malviya Nagar", "Jaipur", "302017", "RJ"),
    ("52 Vaishali Nagar", "Jaipur", "302021", "RJ"),
    ("61 Hazratganj", "Lucknow", "226001", "UP"),
    ("23 Gomti Nagar", "Lucknow", "226010", "UP"),
    ("34 Aliganj Road", "Lucknow", "226024", "UP"),
    ("77 Panampilly Nagar", "Kochi", "682036", "KL"),
    ("14 MG Road", "Kochi", "682016", "KL"),
    ("55 Marine Drive", "Kochi", "682031", "KL"),
    ("28 Kaloor Road", "Kochi", "682017", "KL"),
    ("18 Sector 22", "Chandigarh", "160022", "CH"),
    ("9 Sector 17", "Chandigarh", "160017", "CH"),
    ("19 Sector 35", "Chandigarh", "160022", "CH"),
    ("7 Anna Nagar 2nd Avenue", "Chennai", "600040", "TN"),
    ("88 Velachery Main Road", "Chennai", "600042", "TN"),
    ("121 Andheri Link Road", "Mumbai", "400053", "MH"),
    ("45 Powai Lake Road", "Mumbai", "400076", "MH"),
    ("19 Koramangala 5th Block", "Bengaluru", "560095", "KA"),
    ("203 Whitefield Main Road", "Bengaluru", "560066", "KA"),
    ("11 Rajouri Garden", "New Delhi", "110027", "DL"),
    ("58 Lajpat Nagar", "New Delhi", "110024", "DL"),
    ("5 Salt Lake Sector V", "Kolkata", "700091", "WB"),
    ("48 Rashbehari Avenue", "Kolkata", "700029", "WB"),
    ("112 Ballygunge Circular Road", "Kolkata", "700019", "WB"),
]

# Devanagari street names keyed by (street, city) so the duplicated street
# labels (e.g. "14 MG Road" in two cities) stay unambiguous.
IN_BILLING_STREETS_HI = {
    ("24 Park Street", "Kolkata"): "पार्क स्ट्रीट",
    ("1B Rasheed Place", "Kolkata"): "रशीद प्लेस",
    ("56 Elgin Road", "Kolkata"): "एल्गिन रोड",
    ("8A Gokhale Road", "Kolkata"): "गोखले रोड",
    ("5 Salt Lake Sector V", "Kolkata"): "साल्ट लेक सेक्टर 5",
    ("48 Rashbehari Avenue", "Kolkata"): "रासबिहारी एवेन्यू",
    ("112 Ballygunge Circular Road", "Kolkata"): "बालीगंज सर्कुलर रोड",
    ("14 MG Road", "Bengaluru"): "एमजी रोड",
    ("77 Residency Road", "Bengaluru"): "रेसिडेंसी रोड",
    ("Indiranagar 100 Feet Road", "Bengaluru"): "इंदिरानगर 100 फीट रोड",
    ("12 Brigade Road", "Bengaluru"): "ब्रिगेड रोड",
    ("19 Koramangala 5th Block", "Bengaluru"): "कोरामंगला 5वां ब्लॉक",
    ("203 Whitefield Main Road", "Bengaluru"): "व्हाइटफील्ड मेन रोड",
    ("18 Marine Drive", "Mumbai"): "मरीन ड्राइव",
    ("304 Linking Road", "Mumbai"): "लिंकिंग रोड",
    ("77 Hill Road", "Mumbai"): "हिल रोड",
    ("22 Carter Road", "Mumbai"): "कार्टर रोड",
    ("121 Andheri Link Road", "Mumbai"): "अंधेरी लिंक रोड",
    ("45 Powai Lake Road", "Mumbai"): "पवई लेक रोड",
    ("32 Connaught Place", "New Delhi"): "कनॉट प्लेस",
    ("115 Janpath", "New Delhi"): "जनपथ",
    ("9 Green Park", "New Delhi"): "ग्रीन पार्क",
    ("27 Greater Kailash", "New Delhi"): "ग्रेटर कैलाश",
    ("11 Rajouri Garden", "New Delhi"): "राजौरी गार्डन",
    ("58 Lajpat Nagar", "New Delhi"): "लाजपत नगर",
    ("41 Anna Salai", "Chennai"): "अन्ना सलाई",
    ("33 Cathedral Road", "Chennai"): "कैथेड्रल रोड",
    ("19 Nungambakkam High Road", "Chennai"): "नुंगमबक्कम हाई रोड",
    ("7 Anna Nagar 2nd Avenue", "Chennai"): "अन्ना नगर दूसरा एवेन्यू",
    ("88 Velachery Main Road", "Chennai"): "वेलाचेरी मेन रोड",
    ("55 Jubilee Hills Road", "Hyderabad"): "जुबली हिल्स रोड",
    ("28 Banjara Hills Road", "Hyderabad"): "बंजारा हिल्स रोड",
    ("22 Srinagar Colony Main Road", "Hyderabad"): "श्रीनगर कॉलोनी मेन रोड",
    ("26 Gachibowli Main Road", "Hyderabad"): "गच्चीबावली मेन रोड",
    ("88 FC Road", "Pune"): "एफसी रोड",
    ("23 Law College Road", "Pune"): "लॉ कॉलेज रोड",
    ("15 Aundh Road", "Pune"): "औंध रोड",
    ("39 Viman Nagar Road", "Pune"): "विमान नगर रोड",
    ("21 Koregaon Park Road", "Pune"): "कोरेगांव पार्क रोड",
    ("63 Aundh Baner Road", "Pune"): "औंध बाणेर रोड",
    ("31 CG Road", "Ahmedabad"): "सीजी रोड",
    ("67 Ashram Road", "Ahmedabad"): "आश्रम रोड",
    ("17 Satellite Road", "Ahmedabad"): "सैटेलाइट रोड",
    ("44 MI Road", "Jaipur"): "एमआई रोड",
    ("12 Malviya Nagar", "Jaipur"): "मालवीय नगर",
    ("52 Vaishali Nagar", "Jaipur"): "वैशाली नगर",
    ("61 Hazratganj", "Lucknow"): "हज़रतगंज",
    ("23 Gomti Nagar", "Lucknow"): "गोमती नगर",
    ("34 Aliganj Road", "Lucknow"): "अलीगंज रोड",
    ("77 Panampilly Nagar", "Kochi"): "पनमपिल्ली नगर",
    ("14 MG Road", "Kochi"): "एमजी रोड",
    ("55 Marine Drive", "Kochi"): "मरीन ड्राइव",
    ("28 Kaloor Road", "Kochi"): "कालूर रोड",
    ("18 Sector 22", "Chandigarh"): "सेक्टर 22",
    ("9 Sector 17", "Chandigarh"): "सेक्टर 17",
    ("19 Sector 35", "Chandigarh"): "सेक्टर 35",
}

EMAIL_DOMAINS = ("gmail.com", "outlook.com", "icloud.com", "hotmail.com")

_log_file = LOG_DIR / f"upi_{time.strftime('%Y%m%d-%H%M%S')}.log"
_dump_counter = 0
_proxy_state: dict[str, Any] | None = None
_proxy_state_lock = RLock()
_log_lock = RLock()
_dump_lock = RLock()
_proxy_file_lock = RLock()
_proxy_state_file_lock_local = local()
_proxy_state_signature: tuple[int, int] | None = None
_proxy_redaction_lock = RLock()
_proxy_redaction_values: set[str] = set()
_log_context = local()


def _fingerprint_value(profile: dict[str, Any] | None, *keys: str, default: str = "") -> str:
    if not isinstance(profile, dict):
        return default
    for key in keys:
        value = str(profile.get(key) or "").strip()
        if value:
            return value
    return default


def _load_upi_fingerprint_profile() -> dict[str, str]:
    raw = os.environ.get("UPI_FINGERPRINT_PROFILE", "").strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("UPI_FINGERPRINT_PROFILE 必须是 JSON 对象") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("UPI_FINGERPRINT_PROFILE 必须是 JSON 对象")
    return {str(key): str(value) for key, value in payload.items() if value not in (None, "")}


def _upi_default_chrome_profile(profile: dict[str, Any]) -> dict[str, Any]:
    """Align UPI IN with the current chatgpt.com web client (Chrome 152 / hi-IN).

    仅 HTTP 头/UA 对齐 Chrome 152；TLS 指纹取 curl_cffi 0.15 运行库内置最高
    chrome131（chrome152 在 0.15 发请求时会报 Impersonating ... is not
    supported）。运行库升级后再同步提升 TLS 预设。
    """
    adapted = dict(profile or {})
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
    )
    adapted.update(
        {
            "major": "152",
            "full": "152.0.0.0",
            "ua": ua,
            "user_agent": ua,
            "sec_ch_ua": (
                '"Chromium";v="152", "Not?A_Brand";v="24", '
                '"Google Chrome";v="152"'
            ),
            "sec_ch_ua_full_version_list": (
                '"Chromium";v="152.0.0.0", "Not?A_Brand";v="24.0.0.0", '
                '"Google Chrome";v="152.0.0.0"'
            ),
            "sec_ch_ua_platform": '"Windows"',
            "platform": "Windows",
            "oai_language": "hi-IN",
            "language": "hi-IN",
            "accept_language": "hi-IN,hi;q=0.9",
            "locale": "hi-IN",
            "timezone": "Asia/Kolkata",
            "timezone_id": "Asia/Kolkata",
            "tls_impersonate": "chrome131",
            "tls": "chrome131",
            "tls_client_identifier": "chrome_131",
        }
    )
    return adapted


def resolve_upi_fingerprint(
    access_token: str = "",
    *,
    account_id: str = "",
    mode: str = "sticky",
    attempt: int = 1,
    profile: dict[str, Any] | None = None,
    device_id: str = "",
) -> dict[str, str]:
    """Return the browser fingerprint used by one UPI attempt and its stages."""
    try:
        from ...fingerprint_store import extractor_profile, get_account_fingerprint
        from ...register_profile import random_profile
        from ...session_login import account_context_from_access_token
    except ImportError:  # pragma: no cover - direct CLI fallback
        project_root = SCRIPT_DIR.parents[2]
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        from standalone_core.fingerprint_store import (  # type: ignore
            extractor_profile,
            get_account_fingerprint,
        )
        from standalone_core.register_profile import random_profile  # type: ignore
        from standalone_core.session_login import (  # type: ignore
            account_context_from_access_token,
        )

    normalized_mode = str(mode or "sticky").strip().lower()
    if normalized_mode not in {"sticky", "rotate"}:
        normalized_mode = "sticky"
    configured_profile = dict(profile or {})
    resolved_account = str(account_id or os.environ.get("UPI_ACCOUNT_ID") or "").strip()
    if not resolved_account:
        try:
            resolved_account, email = account_context_from_access_token(access_token)
            resolved_account = resolved_account or email
        except Exception:
            resolved_account = ""
    resolved_account = resolved_account or (
        "upi-token:" + hashlib.sha256(str(access_token or "").encode("utf-8")).hexdigest()
    )
    runtime_device_id = str(device_id or os.environ.get("UPI_DEVICE_ID") or "").strip()
    if configured_profile and _fingerprint_value(configured_profile, "ua", "user_agent"):
        adapted = configured_profile
        runtime_device_id = runtime_device_id or _fingerprint_value(adapted, "device_id")
        normalized_mode = _fingerprint_value(adapted, "mode", default=normalized_mode)
    elif normalized_mode == "rotate":
        profile_obj = random_profile(
            region="IN",
            diversify=True,
            include_mobile=env_bool("UPI_MOBILE_FINGERPRINTS", False),
        )
        runtime_device_id = runtime_device_id or str(uuid.uuid4())
        adapted = extractor_profile(profile_obj, runtime_device_id)
    else:
        profile_obj, stored_device_id = get_account_fingerprint(
            resolved_account,
            region="IN",
            diversify=env_bool("UPI_DIVERSE_FINGERPRINTS", True),
            include_mobile=env_bool("UPI_MOBILE_FINGERPRINTS", False),
        )
        runtime_device_id = runtime_device_id or stored_device_id
        adapted = extractor_profile(profile_obj, runtime_device_id)
    runtime_device_id = runtime_device_id or str(uuid.uuid4())
    adapted = {str(key): str(value) for key, value in adapted.items() if value not in (None, "")}
    # 保留 fingerprint_store/register_profile 生成的浏览器、平台、UA、语言和
    # TLS 组合。只有旧版兼容开关打开时，才覆盖为固定 Chrome/Windows。
    if (
        not (configured_profile and _fingerprint_value(configured_profile, "ua", "user_agent"))
        and env_bool("UPI_FORCE_CHROME_PROFILE", False)
    ):
        adapted = _upi_default_chrome_profile(adapted)
    adapted.update(
        {
            "device_id": runtime_device_id,
            "mode": normalized_mode,
            "account_id": resolved_account,
            "attempt": str(max(1, int(attempt or 1))),
        }
    )
    return adapted


def upi_fingerprint_label(profile: dict[str, Any] | None, device_id: str = "") -> str:
    if not profile:
        return "默认指纹"
    short_device = str(device_id or profile.get("device_id") or "")[:8] or "random"
    return (
        f"{_fingerprint_value(profile, 'summary', 'name', default='fingerprint')} "
        f"id={_fingerprint_value(profile, 'fingerprint_id', default='-')} "
        f"TLS={_fingerprint_value(profile, 'tls_impersonate', default='chrome136')} "
        f"语言={_fingerprint_value(profile, 'oai_language', 'language', 'accept_language', default='en-IN')} "
        f"时区={_fingerprint_value(profile, 'timezone', 'timezone_id', default='Asia/Kolkata')} "
        f"模式={_fingerprint_value(profile, 'mode', default='sticky')} device={short_device}"
    )


def risk_control_failure_message(
    phase: str,
    failures: int,
    proxy_keys: set[str],
    fingerprint: dict[str, Any] | None,
    fingerprint_keys: set[str] | None = None,
) -> str:
    """Build a safe, structured terminal error for repeated upstream risk blocks."""
    profile = fingerprint if isinstance(fingerprint, dict) else {}
    mode = _fingerprint_value(profile, "mode", default="sticky")
    fingerprint_id = _fingerprint_value(profile, "fingerprint_id", default="-")
    return (
        f"{UPI_RISK_CONTROL_REPEATED_ERROR}: "
        f"phase={str(phase or 'unknown').strip().lower()}; "
        f"failures={max(1, int(failures or 1))}; "
        f"unique_proxy_seeds={len(proxy_keys)}; "
        f"unique_fingerprints={len(fingerprint_keys or set())}; "
        f"fingerprint_mode={mode}; fingerprint_id={fingerprint_id}; "
        "reason=unusual_activity"
    )


def redact_log_text(text: str) -> str:
    text = str(text or "")
    with _proxy_redaction_lock:
        values = sorted(_proxy_redaction_values, key=len, reverse=True)
    for value in values:
        if value:
            try:
                label = proxy_label(value)
            except (TypeError, ValueError):
                label = f"proxy#{hashlib.sha256(value.encode()).hexdigest()[:10]}"
            if label == "direct":
                label = f"proxy#{hashlib.sha256(value.encode()).hexdigest()[:10]}"
            text = text.replace(value, label)
    return text


def log(message: str, prefix: str = "") -> None:
    context = getattr(_log_context, "prefix", "")
    line = redact_log_text(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {prefix}{context}{message}")
    with _log_lock:
        # The extractor is also launched as a subprocess on Windows.  Its
        # parent decodes stdout as UTF-8, so keep diagnostics deterministic
        # instead of inheriting the console code page.
        try:
            if hasattr(sys.stdout, "reconfigure") and str(getattr(sys.stdout, "encoding", "") or "").lower() not in {"utf-8", "utf8"}:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
        print(line, flush=True)
        with open(_log_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return max(minimum, default)
    try:
        return max(minimum, int(raw))
    except ValueError:
        return max(minimum, default)


def is_checkout_not_active_error(value: Any) -> bool:
    return "checkout_not_active_session" in str(value)


def is_account_auth_error(value: Any) -> bool:
    """OpenAI 判定「这个 AT 本身不可用」（过期/失效），与出口质量无关。

    实测（2026-10-09）：一批 100 个 AT 的 ``exp`` 全部落在 10-02~10-05，早已过期，
    checkout 第一步就返回 ``HTTP 401 {"code":"token_expired"}``。旧逻辑把它当成
    「checkout 阶段失败」记进 seed 健康度，结果 **52 条 seed 全部进了失败冷却**，
    后续任务表现为「UPI 暂无空闲代理 Seed」「10 并发只跑 2 个」——账号问题被
    误判成代理问题，还连坐污染了整池好出口。

    因此这类错误必须：① 立即停止同号剩余轮次；② **不**记任何代理失败；③ 用明确
    文案回显，让父进程能把它翻译成「请删除后重新导入」。
    """
    text = str(value or "").lower()
    if not text:
        return False
    if UPI_ACCOUNT_AUTH_EXPIRED.lower() in text:
        return True
    return any(
        marker in text
        for marker in (
            "token_expired",
            "token is expired",
            "token_invalidated",
            "authentication token is expired",
            "please try signing in again",
        )
    ) or ("http 401" in text and "checkout" in text)


def access_token_expiry(access_token: str) -> float:
    """读取 AT 的 JWT ``exp``（Unix 秒）；无法判定时返回 0。

    复用 ``session_login.access_token_inspect``；直接以 CLI 方式运行本脚本时
    走本地 base64 回退，保证子进程独立可用。
    """
    raw = str(access_token or "").strip()
    if raw.count(".") < 2:
        return 0.0
    try:
        from ...session_login import access_token_inspect

        return float(access_token_inspect(raw).get("exp") or 0.0)
    except ImportError:  # pragma: no cover - direct CLI fallback
        try:
            project_root = SCRIPT_DIR.parents[2]
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            from standalone_core.session_login import access_token_inspect  # type: ignore

            return float(access_token_inspect(raw).get("exp") or 0.0)
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001 - 解析失败一律放行，交给上游真实判定
        return 0.0
    try:
        part = raw.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        return float(payload.get("exp") or 0.0)
    except Exception:  # noqa: BLE001
        return 0.0


def precheck_access_token(access_token: str) -> str:
    """提链前本地判定 AT 是否已过期；返回空串表示放行。

    放在「加载代理 Seed 之前」：过期号 100% 会在 checkout 第一步拿到 401，
    但那时已经占了并发槽、已经取过 Seed 租约。前置到零代理消耗的入口，
    过期批次就不会再把好出口连坐进冷却，也不会白烧代理流量。
    """
    exp = access_token_expiry(access_token)
    if exp <= 0:
        return ""
    margin = env_int("UPI_AT_EXPIRY_MARGIN", 60, minimum=0)
    remaining = exp - time.time()
    if remaining > margin:
        return ""
    stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp))
    if remaining <= 0:
        return (
            f"{UPI_ACCOUNT_AUTH_EXPIRED}: access token 已过期（exp={stamp}，"
            f"过期 {-remaining / 3600:.1f} 小时）。OpenAI 在 checkout 第一步就会返回 "
            "HTTP 401 token_expired，换代理/换指纹都救不回来；请删除该账号并重新导入新的 AT。"
        )
    return (
        f"{UPI_ACCOUNT_AUTH_EXPIRED}: access token 仅剩 {remaining / 60:.1f} 分钟"
        f"（exp={stamp}），不足以跑完一次提链；请重新导入新的 AT。"
    )


def is_user_already_paid_error(value: Any) -> bool:
    return "user is already paid" in str(value or "").lower()


def is_upi_unavailable_error(value: Any) -> bool:
    text = str(value or "")
    return UPI_UNAVAILABLE_ERROR in text or "当前 checkout 不支持 UPI" in text


def is_upstream_risk_control_error(value: Any) -> bool:
    """Return whether the upstream explicitly asked the client to stop/retry later."""
    lower = str(value or "").lower()
    return "unusual activity" in lower or "try again later" in lower


def random_user_agent() -> str:
    return DEFAULT_USER_AGENT


def random_runtime_version() -> str:
    return os.environ.get("PP_RUNTIME_VERSION", "").strip() or DEFAULT_STRIPE_RUNTIME_VERSION


def stripe_browser_id() -> str:
    return f"{uuid.uuid4()}{uuid.uuid4().hex[:8]}"


def build_email(first_name: str, last_name: str, rng: random.Random | None = None) -> str:
    rng = rng or random
    first = re.sub(r"[^a-z]", "", first_name.lower())
    last = re.sub(r"[^a-z]", "", last_name.lower())
    suffix = rng.randint(10000, 999999)
    domain = rng.choice(EMAIL_DOMAINS)
    if rng.random() < 0.5:
        local = f"{first}.{last}{suffix}"
    else:
        local = f"{first}{last}{suffix}"
    return f"{local}@{domain}"


def normalize_country(country: str) -> str:
    value = str(country or "").strip().upper()
    return value if value in COUNTRY_CURRENCY else "IN"


def currency_for_country(country: str) -> str:
    return COUNTRY_CURRENCY.get(normalize_country(country), "INR")


def payment_browser_locale() -> str:
    return os.environ.get("UPI_BROWSER_LOCALE", "en-IN").strip() or "en-IN"


def payment_elements_locale() -> str:
    return os.environ.get("UPI_ELEMENTS_LOCALE", "en").strip() or "en"


def payment_browser_timezone() -> str:
    return os.environ.get("UPI_BROWSER_TIMEZONE", "Asia/Kolkata").strip() or "Asia/Kolkata"


def saved_payment_value() -> str:
    return os.environ.get("UPI_SAVED_PAYMENT_VALUE", "never").strip() or "never"


def payment_accept_language() -> str:
    locale = payment_browser_locale()
    if locale.lower().startswith("en"):
        return "en-US,en;q=0.9"
    return f"{locale},{locale.split('-', 1)[0]};q=0.9,en;q=0.8"


def normalize_proxy_url(proxy: str) -> str:
    proxy = str(proxy or "").strip()
    if not proxy:
        return ""
    prefixed_four = re.match(
        r"^(?P<scheme>[a-z][a-z0-9+.-]*)://"
        r"(?P<host>\[[^\]]+\]|[^:/\s]+):(?P<port>\d+):"
        r"(?P<user>[^:\s]+):(?P<password>.+)$",
        proxy,
        flags=re.IGNORECASE,
    )
    if prefixed_four:
        item = prefixed_four.groupdict()
        proxy = (
            f"{item['scheme'].lower()}://{item['user']}:{item['password']}"
            f"@{item['host']}:{item['port']}"
        )
    elif "://" not in proxy:
        parts = proxy.split(":")
        if len(parts) >= 4 and parts[1].isdigit():
            host, port, username = parts[0], parts[1], parts[2]
            password = ":".join(parts[3:])
            proxy = (
                f"{default_proxy_scheme()}://{quote(unquote(username), safe='-._~')}:"
                f"{quote(unquote(password), safe='-._~')}@{host}:{port}"
            )
        else:
            proxy = f"{default_proxy_scheme()}://{proxy}"

    parsed = urlsplit(proxy)
    if parsed.username is None and parsed.password is None:
        return proxy

    hostname = parsed.hostname or ""
    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    username = quote(unquote(parsed.username or ""), safe="-._~")
    auth = username
    if parsed.password is not None:
        auth = f"{auth}:{quote(unquote(parsed.password), safe='-._~')}"
    return urlunsplit((parsed.scheme, f"{auth}@{host}", parsed.path, parsed.query, parsed.fragment))


def register_proxy_for_redaction(proxy: str) -> None:
    raw = str(proxy or "").strip()
    if not raw:
        return
    normalized = normalize_proxy_url(raw)
    values = {raw}
    if normalized:
        values.add(normalized)
        decoded = unquote(normalized)
        values.add(decoded)
        parsed = urlsplit(decoded)
        if parsed.netloc:
            values.add(parsed.netloc)
        if parsed.hostname:
            host = parsed.hostname
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            try:
                port = parsed.port
            except ValueError:
                port = None
            values.add(f"{host}:{port}" if port else host)
    with _proxy_redaction_lock:
        _proxy_redaction_values.update(values)


def default_proxy_scheme() -> str:
    raw = os.environ.get("UPI_PROXY_DEFAULT_SCHEME", "http").strip().lower()
    raw = raw[:-3] if raw.endswith("://") else raw
    # 严格模式：配置写什么就用什么，不做 socks5 -> socks5h 的隐式提升。
    # 管理员明确选了 socks5（本地解析 DNS），就按 socks5 发出去；
    # 这样「配置」与「实际生效」永远一致，不会出现"配了没生效"的困惑。
    if raw in ("http", "https", "socks4", "socks4a", "socks5", "socks5h"):
        return raw
    return "http"


def configured_proxy_scheme() -> str:
    """当前**配置**的默认协议（未做任何改写），用于日志与后台回显。"""
    raw = os.environ.get("UPI_PROXY_DEFAULT_SCHEME", "http").strip().lower()
    raw = raw[:-3] if raw.endswith("://") else raw
    return raw or "http"


def warn_dns_resolution_scheme() -> bool:
    """socks5 由本地解析 DNS：提醒本地 DNS 必须干净。

    严格模式下配置写 socks5 就用 socks5，不再隐式提升为 socks5h。
    代价是 DNS 解析发生在服务器本地——若本地 DNS 被污染或指向了别的线路，
    同一个出口可能连到不同节点，排查时容易误判成"出口不稳定"。
    """
    if configured_proxy_scheme() != "socks5":
        return False
    log(
        "出口协议：严格模式使用 socks5（DNS 由本机解析，不做 socks5h 提升）。"
        "请确认服务器本地 DNS 干净且与目标地区一致，否则同一出口可能解析到不同节点；"
        "如需 DNS 也走代理端，请把 scheme 改为 socks5h。",
        "[WARN] ",
    )
    return True


def proxy_short(proxy: str) -> str:
    proxy = normalize_proxy_url(proxy)
    if not proxy:
        return "direct"
    digest = hashlib.sha256(proxy.encode()).hexdigest()[:10]
    return f"proxy#{digest}"


def proxy_label(proxy: str) -> str:
    return proxy_short(proxy)


def proxy_key(proxy: str) -> str:
    proxy = normalize_proxy_url(proxy)
    return hashlib.sha256(proxy.encode()).hexdigest() if proxy else ""


_PROXY_COUNTRY_SELECTOR_RE = re.compile(
    r"(?i)(?P<name>country|region)(?P<separator>[-_=])(?P<value>[a-z]{2}(?:,[a-z]{2})*)"
)


def proxy_chain_key(proxy: str) -> str:
    """Return a redacted identity that stays stable across country rewrites."""
    proxy = unquote(normalize_proxy_url(proxy))
    normalized = _PROXY_COUNTRY_SELECTOR_RE.sub(
        lambda match: f"{match.group('name')}{match.group('separator')}*",
        proxy,
    )
    return hashlib.sha256(normalized.encode()).hexdigest()[:10] if normalized else ""


_SESSION_SELECTOR_RE = re.compile(
    r"(?i)(?P<name>sid|session|sessauto|sess|ssid)(?P<sep>[-_=])[A-Za-z0-9]+"
)


def exit_health_session_granular() -> bool:
    """出口健康键是否按 sticky session 粒度区分（默认开启）。

    实测：``*.proxy001.com`` / ``*.1024proxy.io`` 这类上游，同一账号下每个
    sticky session（``ssid_`` / ``sid-``）会稳定落到**不同**印度出口 IP
    （同一 session 两次请求 IP 相同，不同 session IP 不同）。旧实现把不同
    session 归一化成同一个健康键，导致一个 session 被 block 后，整台 host
    的上千条出口全部被判为冷却，日志表现为「独立出口仅 2 条」并被整池跳过。

    默认按 session 区分（每个 session 是独立出口）；只有上游确实会让不同
    session 复用同一 IP 时才需要关掉，用 ``UPI_EXIT_HEALTH_SESSION_GRANULAR=0``。
    """
    return env_bool("UPI_EXIT_HEALTH_SESSION_GRANULAR", True)


def proxy_exit_key(proxy: str) -> str:
    """出口健康度标识：block 冷却按它去重。

    - 默认（``UPI_EXIT_HEALTH_SESSION_GRANULAR`` 开）：保留 sticky session
      选择器，每个 session 视为一个独立出口——与实测的"每 session 一个 IP"
      一致，避免一个 session 被 block 拖垮整台 host。
    - 关闭时退回旧行为：抹掉 session 选择器，同一上游的不同 session 归一化
      成同一个键，用于"换 session 仍复用同一 IP"的上游。
    """
    value = unquote(normalize_proxy_url(proxy))
    if not value:
        return ""
    normalized = _PROXY_COUNTRY_SELECTOR_RE.sub(
        lambda match: f"{match.group('name')}{match.group('separator')}*",
        value,
    )
    if not exit_health_session_granular():
        normalized = _SESSION_SELECTOR_RE.sub(
            lambda match: f"{match.group('name')}{match.group('sep')}*",
            normalized,
        )
    return hashlib.sha256(normalized.encode()).hexdigest() if normalized else ""


def lease_root_stats() -> dict[str, Any]:
    """Count active leases so parallel tasks can be told why the pool is exhausted."""
    root = proxy_lease_root()
    try:
        entries = list(root.iterdir())
    except OSError:
        return {"root": str(root), "total": 0, "expired": 0, "active": 0, "samples": []}
    now = time.time()
    ttl = proxy_lease_ttl()
    active = 0
    expired = 0
    samples: list[str] = []
    for entry in entries:
        try:
            metadata = json.loads((entry / "owner.json").read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            metadata = {}
        try:
            expires_at = float(metadata.get("expires_at") or 0)
        except (TypeError, ValueError):
            expires_at = 0
        if expires_at:
            is_expired = now >= expires_at
        else:
            try:
                is_expired = now - entry.stat().st_mtime >= ttl
            except OSError:
                is_expired = False
        if is_expired:
            expired += 1
        else:
            active += 1
            owner = str(metadata.get("owner") or "")
            if owner and len(samples) < 4:
                samples.append(owner)
    return {
        "root": str(root),
        "total": len(entries),
        "expired": expired,
        "active": active,
        "samples": samples,
    }


def lease_in_use(proxy: str) -> bool:
    """该 Seed 当前是否被其它存活任务持有租约（只读探测，不抢占）。

    并发匹配用：父进程在预检阶段先剔除已被占用的 Seed，让每个并发任务
    直接挑空闲出口，而不是等子进程抢租约失败后判「暂无空闲代理 Seed」。
    """
    lease = ProxySeedLease(proxy)
    if not lease.key:
        return False
    try:
        if not lease.path.exists():
            return False
    except OSError:
        return False
    return not lease._expired()


def proxy_lease_root() -> Path:
    raw = os.environ.get("UPI_PROXY_LEASE_DIR", "").strip()
    return Path(raw).expanduser() if raw else SCRIPT_DIR / "proxy_leases"


def proxy_lease_ttl() -> int:
    return env_int("UPI_PROXY_LEASE_TTL", 900, minimum=30)


def proxy_lease_wait() -> int:
    return env_int("UPI_PROXY_LEASE_WAIT", 0, minimum=0)


def lease_heartbeat_interval() -> float:
    """租约续租间隔：默认 TTL 的 1/3（下限 20s），可用环境变量覆盖。"""
    default = max(20.0, proxy_lease_ttl() / 3.0)
    raw = os.environ.get("UPI_PROXY_LEASE_HEARTBEAT_INTERVAL", "").strip()
    if not raw:
        return default
    try:
        return max(0.05, float(raw))
    except ValueError:
        return default


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """原子写一个小的 JSON 文件。

    租约续租线程会周期性改写 owner.json，直接 ``write_text`` 会先截断再写，
    并发读方（父进程预检 ``lease_in_use``、看板统计）会读到空文件并抛
    JSONDecodeError。这里先写临时文件再 ``os.replace``，读方永远看到完整内容。
    """
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


class ProxySeedLease:
    """跨进程占用一条 sticky Seed，避免多个任务同时复用同一出口。"""

    def __init__(self, proxy: str) -> None:
        self.proxy = str(proxy or "").strip()
        self.key = proxy_chain_key(self.proxy)
        self.path = proxy_lease_root() / self.key if self.key else Path()
        task_id = str(os.environ.get("UPI_TASK_ID") or "").strip()
        owner_prefix = task_id or f"pid-{os.getpid()}"
        self.owner = f"{owner_prefix}-{uuid.uuid4().hex[:12]}"
        self.acquired = False
        # 租约是否真的落盘。UPI_PROXY_LEASE=0（或 Seed 算不出 key）时 acquire()
        # 只在内存里标记占用，不会创建租约目录；此时 refresh()/_still_holding()/
        # release() 必须全部按「无租约」短路成功，否则续租写 owner.json 必然
        # OSError，主流程会把它误判成「代理租约被其它任务抢占」，导致每个任务
        # 100% 失败在 UPI_PROXY_LEASE_LOST。
        self.persisted = False
        # 长任务续租用：provider/approve 轮询可能远超过 TTL，只做一次性
        # refresh 的话租约会中途过期，被并发任务抢走同一条出口（同一出口被
        # 两个任务同时使用会显著抬高 blocked/风控概率）。
        self._lock = RLock()
        self._heartbeat_stop = Event()
        self._heartbeat: Thread | None = None

    @property
    def metadata_path(self) -> Path:
        return self.path / "owner.json"

    def _metadata(self) -> dict[str, Any]:
        try:
            value = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _expired(self) -> bool:
        metadata = self._metadata()
        try:
            expires_at = float(metadata.get("expires_at") or 0)
        except (TypeError, ValueError):
            expires_at = 0
        if expires_at:
            return time.time() >= expires_at
        try:
            return time.time() - self.path.stat().st_mtime >= proxy_lease_ttl()
        except OSError:
            return False

    def _reclaim_stale(self) -> None:
        # 只处理租约目录内的普通文件（owner.json 与写入中途崩溃留下的 .tmp），
        # 不做递归删除，避免误伤其它路径。
        try:
            entries = list(self.path.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_dir():
                continue
            if entry.name != "owner.json" and not entry.name.endswith(".tmp"):
                continue
            try:
                entry.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                return
        try:
            self.path.rmdir()
        except OSError:
            pass

    def acquire(self) -> bool:
        if not env_bool("UPI_PROXY_LEASE", True) or not self.key:
            self.acquired = True
            self.persisted = False
            return True
        root = proxy_lease_root()
        root.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + proxy_lease_wait()
        while True:
            try:
                self.path.mkdir()
            except FileExistsError:
                if self._expired():
                    self._reclaim_stale()
                    continue
                if time.monotonic() >= deadline:
                    return False
                time.sleep(min(0.2, max(0.01, deadline - time.monotonic())))
                continue
            except OSError:
                return False

            self.acquired = True
            self.persisted = True
            try:
                write_json_atomic(
                    self.metadata_path,
                    {
                        "owner": self.owner,
                        "proxy_key": self.key,
                        "created_at": int(time.time()),
                        "expires_at": int(time.time()) + proxy_lease_ttl(),
                    },
                )
            except OSError:
                self.release()
                return False
            self.start_heartbeat()
            return True

    def _heartbeat_loop(self, interval: float) -> None:
        while not self._heartbeat_stop.wait(interval):
            if not self.acquired:
                return
            if not self._still_holding():
                # 租约被回收或被其它任务接管：立即停止续租并标记丢失，
                # 主流程随后会换新出口，不会两个任务共用同一条出口。
                self.acquired = False
                return
            # 续租写失败（例如 Windows 上读方持有句柄导致 replace 瞬时失败）
            # 不当作租约丢失：下一拍会重试，持有状态由 _still_holding 判定。
            self.refresh()

    def _still_holding(self) -> bool:
        """租约是否仍在手里（文件消失 / owner 易主都算丢失）。"""
        if not self.persisted:
            # 未落盘（租约功能关闭）：没有文件可丢，持有状态只看内存标记。
            return self.acquired
        try:
            if not self.path.exists():
                return False
        except OSError:
            return True
        metadata = self._metadata()
        if not metadata:
            # 读不到内容通常只是并发替换窗口；保守视为仍持有，下一拍再判。
            return True
        return str(metadata.get("owner") or "") == self.owner

    def start_heartbeat(self, interval: float | None = None) -> bool:
        """后台周期续租；返回是否已启动（或已在运行）。"""
        if not self.acquired or not self.key:
            return False
        if not env_bool("UPI_PROXY_LEASE_HEARTBEAT", True):
            return False
        existing = self._heartbeat
        if existing is not None and existing.is_alive():
            return True
        gap = float(interval) if interval is not None else lease_heartbeat_interval()
        self._heartbeat_stop.clear()
        thread = Thread(
            target=self._heartbeat_loop,
            args=(max(0.05, gap),),
            name=f"upi-seed-lease-{self.key[:8]}",
            daemon=True,
        )
        self._heartbeat = thread
        try:
            thread.start()
        except RuntimeError:
            self._heartbeat = None
            return False
        return True

    def refresh(self) -> bool:
        with self._lock:
            if not self.acquired or not self.key:
                return self.acquired
            if not self.persisted:
                # 租约功能关闭：没有 owner.json 可续，直接视为续租成功。
                return True
            metadata = self._metadata()
            if metadata and str(metadata.get("owner") or "") != self.owner:
                self.acquired = False
                return False
            try:
                metadata.update(
                    {
                        "owner": self.owner,
                        "proxy_key": self.key,
                        "expires_at": int(time.time()) + proxy_lease_ttl(),
                    }
                )
                write_json_atomic(self.metadata_path, metadata)
            except OSError:
                return False
            return True

    def release(self) -> None:
        # 先停心跳，再由持锁的本线程删文件：否则心跳可能在租约目录被回收后
        # 把 owner.json 重新写回去（等于把已释放的出口又占住，甚至覆盖下一个
        # 任务的 owner），导致同一出口被两个任务同时使用。
        self._heartbeat_stop.set()
        with self._lock:
            if not self.acquired or not self.key:
                return
            if not self.persisted:
                self.acquired = False
                return
            metadata = self._metadata()
            if metadata and str(metadata.get("owner") or "") != self.owner:
                self.acquired = False
                return
            self.acquired = False
            try:
                self.metadata_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                return
            try:
                self.path.rmdir()
            except OSError:
                pass


def proxy_for_country(proxy: str, country: str) -> str:
    """Rewrite only a proxy auth country selector while retaining its sticky session."""
    proxy = normalize_proxy_url(proxy)
    target_country = normalize_country(country).lower()
    if not proxy:
        raise RuntimeError("代理为空，无法派生地区链路")

    parsed = urlsplit(proxy)
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    replacements = 0

    def replace_country(match: re.Match[str]) -> str:
        nonlocal replacements
        replacements += 1
        current = match.group("value")
        value = target_country.upper() if current.isupper() else target_country
        return f"{match.group('name')}{match.group('separator')}{value}"

    username = _PROXY_COUNTRY_SELECTOR_RE.sub(replace_country, username)
    password = _PROXY_COUNTRY_SELECTOR_RE.sub(replace_country, password)
    if not replacements:
        # API-returned host:port proxies are already concrete exits. Reuse as-is for this account.
        register_proxy_for_redaction(proxy)
        return proxy

    hostname = parsed.hostname or ""
    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    auth = quote(username, safe="-._~")
    if parsed.password is not None:
        auth = f"{auth}:{quote(password, safe='-._~')}"
    derived = urlunsplit((parsed.scheme, f"{auth}@{host}", parsed.path, parsed.query, parsed.fragment))
    register_proxy_for_redaction(derived)
    return derived


def upi_proxy_chain(proxy_seed: str) -> tuple[str, str, str]:
    """Keep one sticky seed across configured checkout, promotion, and provider stages."""
    checkout_proxy = proxy_for_country(proxy_seed, UPI_BOOTSTRAP_COUNTRY)
    promotion_proxies = [
        proxy_for_country(proxy_seed, country) for country in UPI_PROMOTION_COUNTRIES
    ]
    provider_proxy = proxy_for_country(proxy_seed, UPI_PROVIDER_COUNTRY)
    chain_key = proxy_chain_key(proxy_seed)
    if not chain_key or any(
        proxy_chain_key(proxy) != chain_key
        for proxy in (checkout_proxy, *promotion_proxies, provider_proxy)
    ):
        raise RuntimeError("代理地区改写改变了 sticky seed，已拒绝混用代理链")
    return checkout_proxy, promotion_proxies[0], provider_proxy


def log_upi_proxy_chain(proxy_seed: str, checkout_proxy: str, promotion_proxy: str, provider_proxy: str) -> None:
    promotion_steps = " -> ".join(
        f"{country} promotion={proxy_label(proxy_for_country(promotion_proxy, country))}"
        for country in UPI_PROMOTION_COUNTRIES
    )
    log(
        "派生代理链: "
        f"chain={proxy_chain_key(proxy_seed)}; seed={proxy_label(proxy_seed)}; "
        f"{UPI_BOOTSTRAP_COUNTRY} checkout={proxy_label(checkout_proxy)}; "
        f"{promotion_steps}; "
        f"{UPI_PROVIDER_COUNTRY} provider/approve={proxy_label(provider_proxy)}"
    )


def normalize_pre_proxy_url(proxy: str) -> str:
    proxy = str(proxy or "").strip()
    if not proxy:
        return ""
    if "://" not in proxy:
        proxy = f"socks5h://{proxy}"
    return normalize_proxy_url(proxy)


def proxy_state_path() -> Path:
    raw = os.environ.get("UPI_PROXY_STATE_FILE", "").strip()
    return Path(raw) if raw else SCRIPT_DIR / "proxy_state.json"


@contextmanager
def _proxy_state_os_lock():
    """跨进程保护 proxy_state.json 的读改写。

    ``RLock`` 只能覆盖当前 Python 进程；服务重启、并发 worker 或多个
    standalone 实例同时更新状态时，仍可能出现半截 JSON 或后写覆盖先写。
    锁文件保持不删除，避免进程在加锁期间替换锁文件导致锁失效。
    """
    lock_path = proxy_state_path().with_name(f".{proxy_state_path().name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    depth = int(getattr(_proxy_state_file_lock_local, "depth", 0) or 0)
    if depth:
        _proxy_state_file_lock_local.depth = depth + 1
        try:
            yield
        finally:
            _proxy_state_file_lock_local.depth = depth
        return

    with lock_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    handle.seek(0)
                    time.sleep(0.05)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        _proxy_state_file_lock_local.depth = 1
        try:
            yield
        finally:
            _proxy_state_file_lock_local.depth = 0
            if os.name == "nt":
                handle.seek(0)
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _write_proxy_state_atomic(path: Path, state: dict[str, Any]) -> None:
    """原子落盘，避免进程中断时留下半截 proxy_state.json。"""
    global _proxy_state_signature
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        try:
            stat = path.stat()
            _proxy_state_signature = (int(stat.st_mtime_ns), int(stat.st_size))
        except OSError:
            _proxy_state_signature = None
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


@contextmanager
def _proxy_state_transaction():
    """在跨进程锁内完成一次完整的 proxy state 读改写事务。"""
    global _proxy_state
    with _proxy_state_lock:
        with _proxy_file_lock:
            with _proxy_state_os_lock():
                _proxy_state = None
                state = load_proxy_state()
                yield state
                if _proxy_state is not None:
                    _write_proxy_state_atomic(proxy_state_path(), _proxy_state)


def exit_health_enabled() -> bool:
    """出口健康门禁：同一出口在窗口内出现过 block 就临时停用。"""
    return env_bool("UPI_EXIT_HEALTH", True)


def exit_block_window_seconds() -> int:
    return env_int("UPI_EXIT_BLOCK_WINDOW", 3600, minimum=60)


def exit_health_max_blocks() -> int:
    """窗口内允许的 block 次数；达到即停用该出口（默认 1 = 一次就停）。"""
    return env_int("UPI_EXIT_HEALTH_MAX_BLOCKS", 1, minimum=1)


def exit_health_ttl_seconds() -> int:
    """没有 block 记录时的使用计数保留时长，避免状态文件无限增长。"""
    return env_int("UPI_EXIT_HEALTH_TTL", 86400, minimum=60)


def exit_health_min_pool() -> int:
    """低于这个独立出口数时，冷却自动放宽，避免小池被自己的冷却锁死。"""
    return env_int("UPI_EXIT_HEALTH_MIN_POOL", 3, minimum=1)


def exit_health_remaining_seconds(proxy: str) -> int:
    """该出口的 block 冷却剩余秒数；未冷却返回 0。"""
    if not proxy or not exit_health_enabled():
        return 0
    key = proxy_exit_key(proxy)
    if not key:
        return 0
    now = int(time.time())
    with _proxy_state_lock:
        state = load_proxy_state()
        record = (state.get("exit_health") or {}).get(key) or {}
    if not isinstance(record, dict):
        return 0
    until = int(record.get("blocked_until") or 0)
    return max(0, until - now)


def _pool_exit_count_estimate(proxies: list[str]) -> int:
    """池内独立出口数（按出口键去重）。"""
    return len({proxy_exit_key(item) for item in proxies if proxy_exit_key(item)})


_RISK_BLOCK_MARKERS = (
    # OpenAI 侧的人工审批拒绝：链路已走完，是"这个出口这次没通过审批"，
    # 换出口确实有几率改变结果 → 计入出口冷却。
    "unusual activity",
    "try again later",
    "approve blocked",
    "manual_approval approve rejected",
    "approve 未通过",
    "approve rejected",
    "approve 被拒",
    "payment was not approved",
    # 注意：``generic_decline`` / ``requires_payment_method`` 故意不在此列。
    #
    # 实测的失败顺序是**串联闸门**：
    #   ① stripe_confirm_upi → raise_if_setup_intent_blocked  ← 在这里抛 generic_decline
    #   ② resolve_confirm_payload_upi → approve_with_retry    ← 只有 ① 通过才会执行
    # （见 resolve_confirm_payload_upi 函数体第一行就是 raise_if_setup_intent_blocked）
    #
    # 也就是说 generic_decline 出现在 **approve 之前**：该账号连 UPI 委托都没签成，
    # 属于**账号资格耗尽**，与出口质量无关。把它算进出口冷却会误伤好出口，
    # 让本该继续使用的出口被无谓停用（实测 3/6 个号命中，会连锁关停一批正常出口）。
    # 它仍然由 ``is_account_level_failure`` 处理：立即停止该账号的剩余轮次。
)


def is_exit_risk_block(reason: str) -> bool:
    """把「上游风控/审批拒绝」类结果识别出来，用于出口冷却。

    注意：出口层故障（TLS/超时/连接重置）由 ``is_proxy_health_failure`` 处理，
    本函数只认「账号维度被拒」，两者不能混用——否则会把坏出口和坏账号一起惩罚。
    """
    text = str(reason or "").lower()
    return any(marker in text for marker in _RISK_BLOCK_MARKERS)


def record_exit_risk_block(proxy: str, reason: str, fingerprint_id: str = "") -> bool:
    """标记某个出口刚触发过 block；返回本次是否达到停用阈值。

    这是「IP 撞烂」防护的核心：同一个出口如果在窗口内 block 过，就说明它当前
    的风控画像已经脏了，继续拿它打别的账号只会把账号一起带下去。
    """
    if not proxy or not exit_health_enabled():
        return False
    key = proxy_exit_key(proxy)
    if not key:
        return False
    window = exit_block_window_seconds()
    threshold = exit_health_max_blocks()
    now = int(time.time())
    with _proxy_state_transaction() as state:
        health = state.setdefault("exit_health", {})
        record = health.setdefault(key, {})
        events = [int(item) for item in (record.get("blocks") or []) if int(item) > now - window]
        events.append(now)
        record["blocks"] = events
        record["block_count"] = len(events)
        record["last_block"] = now
        record["last_reason"] = redact_log_text(str(reason or ""))[:160]
        record["label"] = proxy_label(proxy)
        if fingerprint_id:
            recent_fps = [str(item) for item in (record.get("fingerprints") or []) if item]
            recent_fps.append(str(fingerprint_id))
            record["fingerprints"] = recent_fps[-10:]
        blocked = len(events) >= threshold
        if blocked:
            record["blocked_until"] = now + window
    if blocked:
        log(
            f"出口 {record['label']} 在 {window // 60} 分钟内已 block {len(events)} 次"
            f"（阈值 {threshold}），已临时停用至 {time.strftime('%H:%M:%S', time.localtime(record['blocked_until']))}；"
            "同一出口连续 trigger 会把不同账号一起带下去，换出口比换号更划算",
            "[WARN] ",
        )
    return blocked


def record_exit_usage(proxy: str) -> None:
    """记录出口被使用一次（含成功），用于健康度统计与陈旧记录回收。"""
    if not proxy or not exit_health_enabled():
        return
    key = proxy_exit_key(proxy)
    if not key:
        return
    now = int(time.time())
    with _proxy_state_transaction() as state:
        health = state.setdefault("exit_health", {})
        record = health.setdefault(key, {})
        record["uses"] = int(record.get("uses") or 0) + 1
        record["last_use"] = now
        record.setdefault("label", proxy_label(proxy))


def record_exit_success(proxy: str) -> None:
    """出口出链成功：清掉它的 block 记录，让它重新可用。"""
    if not proxy or not exit_health_enabled():
        return
    key = proxy_exit_key(proxy)
    if not key:
        return
    with _proxy_state_transaction() as state:
        health = state.setdefault("exit_health", {})
        record = health.get(key)
        if isinstance(record, dict) and record.get("blocks"):
            record["blocks"] = []
            record["block_count"] = 0
            record["blocked_until"] = 0
            record["cleared_at"] = int(time.time())
            log(f"出口 {record.get('label') or proxy_label(proxy)} 已出链，block 冷却解除")


def exit_health_block_reason(proxy: str) -> str:
    """该出口是否正处于 block 冷却期；返回可读原因，未冷却返回空串。"""
    if not proxy or not exit_health_enabled():
        return ""
    key = proxy_exit_key(proxy)
    if not key:
        return ""
    window = exit_block_window_seconds()
    threshold = exit_health_max_blocks()
    now = int(time.time())
    with _proxy_state_lock:
        state = load_proxy_state()
        record = (state.get("exit_health") or {}).get(key) or {}
    if not isinstance(record, dict):
        return ""
    events = [int(item) for item in (record.get("blocks") or []) if int(item) > now - window]
    if len(events) < threshold:
        return ""
    until = int(record.get("blocked_until") or (max(events) + window))
    if until <= now:
        return ""
    return (
        f"出口 {str(record.get('label') or proxy_label(proxy))} 处于 block 冷却"
        f"（{len(events)} 次/{window // 60} 分钟，剩余 {max(0, until - now)} 秒）"
    )


def prune_exit_health() -> int:
    """清掉既无 block 又长期未使用的出口记录，顺便回收 counts 里的陈旧条目。"""
    ttl = exit_health_ttl_seconds()
    now = int(time.time())
    removed = 0
    with _proxy_state_transaction() as state:
        health = state.get("exit_health")
        if not isinstance(health, dict):
            return 0
        for key in list(health.keys()):
            record = health.get(key)
            if not isinstance(record, dict):
                health.pop(key, None)
                removed += 1
                continue
            last_block = int(record.get("last_block") or 0)
            last_use = int(record.get("last_use") or 0)
            if not last_block and last_use and now - last_use > ttl:
                health.pop(key, None)
                removed += 1
    return removed


def load_proxy_state() -> dict[str, Any]:
    global _proxy_state, _proxy_state_signature
    with _proxy_state_lock:
        path = proxy_state_path()
        try:
            stat = path.stat()
            signature = (int(stat.st_mtime_ns), int(stat.st_size))
        except OSError:
            signature = None
        if _proxy_state is not None and _proxy_state_signature == signature:
            return _proxy_state
        if not path.exists():
            _proxy_state = {"seed": {}, "checkout": {}, "promotion": {}, "provider": {}, "pair": {}}
            _proxy_state_signature = None
            return _proxy_state
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("seed", {})
        data.setdefault("checkout", {})
        data.setdefault("promotion", {})
        data.setdefault("provider", {})
        data.setdefault("pair", {})
        data.setdefault("exit_health", {})
        _proxy_state = data
        _proxy_state_signature = signature
        return _proxy_state


def save_proxy_state() -> None:
    with _proxy_state_lock:
        if _proxy_state is None:
            return
        with _proxy_file_lock:
            with _proxy_state_os_lock():
                _write_proxy_state_atomic(proxy_state_path(), _proxy_state)


def proxy_state_key(group: str, proxy: str) -> str:
    if group == "seed":
        return proxy_chain_key(proxy)
    return proxy_key(proxy)


def record_checkout_provider(provider: str, cs_id: str = "") -> dict[str, Any]:
    """统计 OpenAI 把建单分流到哪个通道（stripe=`cs_live_` / open_ai=`oaics_`）。

    这是观察项：``oaics_`` 由 OpenAI 服务端按账号灰度分配，客户端无法选择，
    所以只能累计命中率来判断「强制 OAICS / mandate_options」这条路是否可达。
    计数写入 ``proxy_state.json`` 的 ``provider_stats`` 段，跨进程持久化。
    """
    name = str(provider or "").strip().lower() or "unknown"
    kind = "oaics" if str(cs_id or "").startswith("oaics_") else (
        "cs_live" if str(cs_id or "").startswith("cs_") else "unknown"
    )
    summary: dict[str, Any] = {}
    with _proxy_state_transaction() as state:
        stats = state.setdefault("provider_stats", {})
        for key, value in (("total", 1), (f"provider:{name}", 1), (f"kind:{kind}", 1)):
            stats[key] = int(stats.get(key) or 0) + value
        stats["last_provider"] = name
        stats["last_kind"] = kind
        stats["last_cs_prefix"] = str(cs_id or "")[:14] or "-"
        stats["updated_at"] = int(time.time())
        summary = {
            "total": stats["total"],
            "stripe": int(stats.get("provider:stripe") or 0),
            "open_ai": int(stats.get("provider:open_ai") or 0),
            "oaics": int(stats.get("kind:oaics") or 0),
            "cs_live": int(stats.get("kind:cs_live") or 0),
        }
    return summary


def prune_proxy_seed_state(proxy_seeds: list[str]) -> None:
    with _proxy_state_transaction() as state:
        seed_state = state.setdefault("seed", {})
        active_keys = {proxy_chain_key(proxy) for proxy in proxy_seeds if proxy_chain_key(proxy)}
        stale_keys = [key for key in seed_state if key not in active_keys]
        for key in stale_keys:
            del seed_state[key]
    if stale_keys:
        log(f"Seed 代理状态清理完成: {len(stale_keys)}")


def prune_proxy_state(checkout_proxies: list[str], promotion_proxies: list[str], provider_proxies: list[str]) -> None:
    removed_counts: dict[str, int] = {}
    with _proxy_state_transaction() as state:
        active_keys_by_group: dict[str, set[str]] = {}
        for group, proxies in (
            ("checkout", checkout_proxies),
            ("promotion", promotion_proxies),
            ("provider", provider_proxies),
        ):
            group_state = state.get(group)
            if not isinstance(group_state, dict):
                continue
            active_keys = {proxy_key(proxy) for proxy in proxies if proxy}
            active_keys_by_group[group] = active_keys
            stale_keys = [key for key in group_state if key not in active_keys]
            for key in stale_keys:
                del group_state[key]
            if stale_keys:
                removed_counts[group] = len(stale_keys)
        pair_state = state.get("pair")
        if isinstance(pair_state, dict):
            active_checkout = active_keys_by_group.get("checkout", set())
            active_provider = active_keys_by_group.get("provider", set())
            stale_pair_keys = [
                key
                for key, record in pair_state.items()
                if not isinstance(record, dict)
                or record.get("checkout") not in active_checkout
                or record.get("provider") not in active_provider
            ]
            for key in stale_pair_keys:
                del pair_state[key]
            if stale_pair_keys:
                removed_counts["pair"] = len(stale_pair_keys)
    if removed_counts:
        summary = ", ".join(f"{group}={count}" for group, count in removed_counts.items())
        log(f"代理状态清理完成: {summary}")


def proxy_record(group: str, proxy: str) -> dict[str, Any]:
    with _proxy_state_lock:
        state = load_proxy_state()
        group_state = state.setdefault(group, {})
        key = proxy_state_key(group, proxy)
        if not key:
            return {}
        record = group_state.setdefault(key, {})
        record.setdefault("success", 0)
        record.setdefault("fail", 0)
        return record


def proxy_pair_key(checkout_proxy: str, provider_proxy: str) -> str:
    checkout_key = proxy_key(checkout_proxy)
    provider_key = proxy_key(provider_proxy)
    return f"{checkout_key}:{provider_key}" if checkout_key and provider_key else ""


def _apply_proxy_result(
    state: dict[str, Any],
    group: str,
    proxy: str,
    success: bool,
    reason: str = "",
) -> dict[str, Any]:
    """把一条出口结果写进已打开的 state（调用方负责事务与落盘）。"""
    if not proxy:
        return {}
    group_state = state.setdefault(group, {})
    key = proxy_state_key(group, proxy)
    if not key:
        return {}
    record = group_state.setdefault(key, {})
    record.setdefault("success", 0)
    record.setdefault("fail", 0)
    now = int(time.time())
    if success:
        record["success"] = int(record.get("success") or 0) + 1
        record["fail"] = 0
        record["last_success"] = now
        record["last_reason"] = "success"
    else:
        record["fail"] = int(record.get("fail") or 0) + 1
        record["last_fail"] = now
        record["last_reason"] = str(reason or "failed")[:160]
    return record


def record_proxy_result(group: str, proxy: str, success: bool, reason: str = "") -> dict[str, Any]:
    if not proxy or not env_bool("UPI_PROXY_SCORE", True):
        return {}
    with _proxy_state_transaction() as state:
        return _apply_proxy_result(state, group, proxy, success, reason)


def record_proxy_results_batch(
    group: str, items: list[tuple[str, bool, str]]
) -> int:
    """一次事务写入多条出口结果（父进程预检批量回写，避免每条一落盘）。

    线上代理池大面积被服务商拒绝（HTTP 809）时，预检每轮都会得出上百条结论；
    逐条写 proxy_state.json 既慢又会反复重写整份文件，这里合并成一次写入。
    """
    if not items or not env_bool("UPI_PROXY_SCORE", True):
        return 0
    updated = 0
    with _proxy_state_transaction() as state:
        for proxy, success, reason in items:
            if _apply_proxy_result(state, group, proxy, success, reason):
                updated += 1
    return updated


def proxy_remove_after_fails() -> int:
    return env_int("UPI_PROXY_REMOVE_AFTER_FAILS", 3)


def is_reused_proxy_record(group: str, record: dict[str, Any]) -> bool:
    return int(record.get("success") or 0) > 0


def record_proxy_health_failure(group: str, proxy: str, reason: str) -> None:
    record = record_proxy_result(group, proxy, False, reason)
    fail_count = int(record.get("fail") or 0)
    remove_after = proxy_remove_after_fails() if is_reused_proxy_record(group, record) else 1
    if fail_count >= remove_after:
        remove_failed_proxy(group, proxy, reason)


def checkout_zero_cache_ttl() -> int:
    return env_int("UPI_ZERO_CACHE_TTL", 86400, minimum=0)


def zero_cache_scheduling_enabled() -> bool:
    return env_bool("UPI_ZERO_CACHE_SCHEDULING", False)


def checkout_zero_cache_status(proxy: str, country: str) -> tuple[str, int, int]:
    if not proxy or not env_bool("UPI_ZERO_CACHE", True):
        return "", 0, 0
    record = proxy_record("seed", proxy)
    if not record:
        return "", 0, 0
    checked_at = int(record.get("zero_checked_at") or 0)
    if not checked_at:
        return "", 0, 0
    ttl = checkout_zero_cache_ttl()
    if ttl > 0 and int(time.time()) - checked_at > ttl:
        return "", 0, checked_at
    if normalize_country(str(record.get("zero_country") or country)) != normalize_country(country):
        return "", 0, checked_at
    amount = int(record.get("zero_amount") or 0)
    if record.get("zero_ok") is True:
        return "ok", amount, checked_at
    if record.get("zero_ok") is False:
        return "bad", amount, checked_at
    return "", amount, checked_at


def record_checkout_zero_result(proxy: str, country: str, amount: int) -> None:
    if not proxy or not env_bool("UPI_ZERO_CACHE", True):
        return
    with _proxy_state_transaction() as state:
        key = proxy_state_key("seed", proxy)
        if not key:
            return
        record = state.setdefault("seed", {}).setdefault(key, {})
        record.setdefault("success", 0)
        record.setdefault("fail", 0)
        amount = int(amount or 0)
        record["zero_ok"] = amount == 0
        record["zero_amount"] = amount
        record["zero_country"] = normalize_country(country)
        record["zero_checked_at"] = int(time.time())
        if amount == 0:
            record["zero_success"] = int(record.get("zero_success") or 0) + 1


def record_proxy_pair_result(checkout_proxy: str, provider_proxy: str, success: bool, reason: str = "") -> None:
    record_proxy_result("checkout", checkout_proxy, success, reason)
    record_proxy_result("provider", provider_proxy, success, reason)
    if not checkout_proxy or not provider_proxy or not env_bool("UPI_PROXY_SCORE", True):
        return
    key = proxy_pair_key(checkout_proxy, provider_proxy)
    if not key:
        return
    with _proxy_state_transaction() as state:
        pair_state = state.setdefault("pair", {})
        record = pair_state.setdefault(
            key,
            {"checkout": proxy_key(checkout_proxy), "provider": proxy_key(provider_proxy)},
        )
        now = int(time.time())
        if success:
            record["success"] = int(record.get("success") or 0) + 1
            record["fail"] = 0
            record["last_success"] = now
            record["last_reason"] = "success"
        else:
            record["fail"] = int(record.get("fail") or 0) + 1
            record["last_fail"] = now
            record["last_reason"] = str(reason or "failed")[:160]


def record_proxy_pair_approve_success(checkout_proxy: str, provider_proxy: str, approve_proxy: str) -> None:
    if not checkout_proxy or not provider_proxy or not approve_proxy or not env_bool("UPI_PROXY_SCORE", True):
        return
    key = proxy_pair_key(checkout_proxy, provider_proxy)
    approve_key = proxy_key(approve_proxy)
    if not key or not approve_key:
        return
    record_proxy_result("provider", approve_proxy, True, "approve_success")
    with _proxy_state_transaction() as state:
        pair_state = state.setdefault("pair", {})
        record = pair_state.setdefault(
            key,
            {"checkout": proxy_key(checkout_proxy), "provider": proxy_key(provider_proxy)},
        )
        now = int(time.time())
        record["approve"] = approve_key
        record["approve_success"] = int(record.get("approve_success") or 0) + 1
        record["approve_last_success"] = now
        record["approve_last_reason"] = "success"


def pick_proxy_bucketed(
    proxies: list[str],
    group: str,
    *,
    cooldown_seconds: int = 300,
    prefer_recent: bool = False,
) -> str:
    """Pick one proxy biased by historical success rate (A/B style).

    Score = success - 2 * recent_failures within ``cooldown_seconds``, plus a
    small bonus when ``prefer_recent`` and the proxy succeeded recently.
    Ties are resolved randomly among the top scorers so a fresh pool does not
    always start from ``proxies[0]``.
    """
    if not proxies:
        return ""
    if not env_bool("UPI_PROXY_SCORE", True):
        return proxies[secrets.randbelow(len(proxies))]
    now = int(time.time())
    with _proxy_state_lock:
        state = load_proxy_state()
        group_state = state.get(group) or {}
    scored: list[tuple[float, int, str]] = []
    for index, proxy in enumerate(proxies):
        if not proxy:
            continue
        record = group_state.get(proxy_state_key(group, proxy)) or {}
        success = int(record.get("success") or 0)
        last_fail = int(record.get("last_fail") or 0)
        last_success = int(record.get("last_success") or 0)
        recent_failures = 1 if last_fail and (now - last_fail) <= cooldown_seconds else 0
        score = float(success) - 2.0 * float(recent_failures)
        if prefer_recent and last_success and (now - last_success) <= cooldown_seconds:
            score += 0.25
        scored.append((score, -index, proxy))
    if not scored:
        return proxies[0]
    scored.sort(key=lambda item: (-item[0], item[1]))
    best_score = scored[0][0]
    tied = [proxy for score, _, proxy in scored if score == best_score]
    return tied[secrets.randbelow(len(tied))]


def successful_approve_preferences(checkout_proxy: str, provider_proxy: str, approve_pool: list[str]) -> list[str]:
    if not env_bool("UPI_PROXY_SCORE", True):
        return []
    pair_state = load_proxy_state().get("pair", {})
    if not isinstance(pair_state, dict):
        return []
    record = pair_state.get(proxy_pair_key(checkout_proxy, provider_proxy))
    if not isinstance(record, dict):
        return []
    approve_key = str(record.get("approve") or "")
    if not approve_key:
        return []
    approve_by_key = {proxy_key(proxy): proxy for proxy in approve_pool}
    approve_proxy = approve_by_key.get(approve_key)
    return [approve_proxy] if approve_proxy else []


def record_failure_by_stage(
    reason: str,
    checkout_proxy: str,
    provider_proxy: str,
    promotion_proxy: str = "",
) -> None:
    def record_seed_failure(proxy: str) -> None:
        if not proxy:
            return
        if is_direct_remove_proxy_error(reason):
            remove_failed_proxy("seed", proxy, reason)
            record_proxy_result("seed", proxy, False, reason)
        elif is_proxy_health_failure(reason):
            record_proxy_health_failure("seed", proxy, reason)
        else:
            record_proxy_result("seed", proxy, False, reason)

    if is_account_auth_error(reason):
        # AT 过期/失效属于账号级失败：这条出口本身可能是好的，不能记失败，
        # 否则一批过期号就能把整池 seed 推进冷却（实测 52 条 seed 被连坐）。
        return
    if "checkout 阶段失败" in reason or "checkout 创建失败" in reason:
        record_seed_failure(checkout_proxy)
        return
    if is_upi_unavailable_error(reason):
        return
    if "0 元优惠未生效" in reason:
        return
    if "approve blocked" in reason:
        # 以前这里直接 return，等于「block 完全不记账」，同一个脏出口会被继续
        # 拿去打下一个账号。现在把 block 记到出口健康度上，触发窗口冷却。
        record_exit_risk_block(checkout_proxy or promotion_proxy or provider_proxy, reason)
        return
    if "promotion 阶段失败" in reason or "checkout/update" in reason:
        record_seed_failure(promotion_proxy)
        return
    if is_exit_risk_block(reason):
        record_exit_risk_block(checkout_proxy or provider_proxy, reason)
        return
    record_seed_failure(provider_proxy)


def order_proxy_group(group: str, proxies: list[str]) -> list[str]:
    if not env_bool("UPI_PROXY_SCORE", True):
        return proxies
    state = load_proxy_state().get(group, {})
    skip_failed = env_bool("UPI_PROXY_SKIP_FAILED", True)
    fail_threshold = env_int("UPI_PROXY_FAIL_SKIP_AFTER", 1)
    fail_cooldown = env_int("UPI_PROXY_FAIL_COOLDOWN", 180, minimum=0)
    zero_ttl = checkout_zero_cache_ttl()
    zero_scheduling = zero_cache_scheduling_enabled()
    now = int(time.time())
    kept: list[str] = []
    cooldown_skipped = 0
    zero_skipped = 0
    exit_health_skipped = 0
    zero_seen = 0
    success_seen = 0
    # 冷却是否生效：池子太小时自动放宽，否则 8 条固定出口被全部冷却后
    # 任务会以「代理 Seed 已全部处于失败冷却」0 秒失败（实测踩过）。
    exit_count = _pool_exit_count_estimate(proxies)
    relaxed_reason = ""
    cooling_active = exit_health_enabled()
    if cooling_active and exit_count < exit_health_min_pool():
        cooling_active = False
        relaxed_reason = (
            f"独立出口仅 {exit_count} 条（< {exit_health_min_pool()}），"
            "已自动放宽 block 冷却以保证任务可执行"
        )
    for proxy in proxies:
        record = state.get(proxy_state_key(group, proxy), {}) if isinstance(state, dict) else {}
        success_count = int(record.get("success") or 0)
        fail_count = int(record.get("fail") or 0)
        last_fail = int(record.get("last_fail") or 0)
        if success_count > 0:
            success_seen += 1
        zero_checked_at = int(record.get("zero_checked_at") or 0)
        zero_cache_valid = zero_checked_at and (zero_ttl <= 0 or now - zero_checked_at <= zero_ttl)
        if group == "checkout" and zero_scheduling and zero_cache_valid and record.get("zero_ok") is True:
            zero_seen += 1
        if (
            group == "checkout"
            and zero_scheduling
            and env_bool("UPI_ZERO_CACHE_SKIP_BAD", True)
            and zero_cache_valid
            and record.get("zero_ok") is False
        ):
            zero_skipped += 1
            continue
        if cooling_active and exit_health_block_reason(proxy):
            # 出口在窗口内 block 过 → 本轮先不用它，别拿它去撞下一个账号。
            # 注意这里是"优先避开"而非"绝对禁止"：若整个池子都被冷却，
            # 下面的兜底会把它们按冷却最浅的顺序放回来，保证不会零候选。
            exit_health_skipped += 1
            continue
        if skip_failed and fail_count >= fail_threshold:
            in_cooldown = fail_cooldown <= 0 or not last_fail or now - last_fail <= fail_cooldown
            if in_cooldown:
                cooldown_skipped += 1
                continue
        kept.append(proxy)

    if relaxed_reason:
        log(f"{group} block 冷却已放宽：{relaxed_reason}", "[WARN] ")

    # 兜底：所有出口都被冷却时，退化为「冷却最浅的先用」而不是直接判失败。
    # 宁可冒险用一个次优出口，也不能让任务 0 秒退出。
    if not kept and proxies:
        cooling = [
            item for item in proxies if exit_health_remaining_seconds(item) > 0
        ]
        if cooling:
            cooling.sort(key=exit_health_remaining_seconds)
            kept = cooling
            log(
                f"{group} 全部 {len(proxies)} 条出口都处于 block 冷却，"
                f"已按「冷却最浅优先」放回 {len(cooling)} 条继续尝试"
                f"（最短剩余 {exit_health_remaining_seconds(cooling[0])}s）；"
                "建议扩充出口池或降低并发，避免小池被自身冷却反复锁死",
                "[WARN] ",
            )
        else:
            log(f"{group} 代理状态过滤后为空，已全部跳过", "[WARN] ")

    def rank(proxy: str) -> tuple[int, int, int, int, int]:
        record = state.get(proxy_state_key(group, proxy), {}) if isinstance(state, dict) else {}
        zero_checked_at = int(record.get("zero_checked_at") or 0)
        zero_cache_valid = zero_checked_at and (zero_ttl <= 0 or now - zero_checked_at <= zero_ttl)
        zero_rank = 1 if group == "checkout" and zero_scheduling and zero_cache_valid and record.get("zero_ok") is True else 0
        return (
            zero_rank,
            int(record.get("success") or 0),
            int(record.get("last_success") or 0),
            -int(record.get("fail") or 0),
            -int(record.get("last_fail") or 0),
        )

    ordered = sorted(kept, key=rank, reverse=True)
    if cooldown_skipped or success_seen or zero_seen or zero_skipped or exit_health_skipped:
        log(
            f"{group} 代理状态: 成功优先={success_seen}，0元命中={zero_seen}，"
            f"冷却跳过={cooldown_skipped}，0元失败跳过={zero_skipped}，"
            f"block冷却跳过={exit_health_skipped}"
        )
    return ordered


def set_proxy(session: Any, proxy: str) -> None:
    register_proxy_for_redaction(proxy)
    proxy = normalize_proxy_url(proxy)
    if hasattr(session, "set_proxy"):
        session.set_proxy(proxy)
        return
    if hasattr(session, "trust_env"):
        session.trust_env = False
    session.proxies = {"http": proxy, "https": proxy} if proxy else {}


def pre_proxy_url() -> str:
    """本机前置代理：本机代理 -> 文件代理 -> 目标站。"""
    for name in ("UPI_PRE_PROXY", "PP_PRE_PROXY", "PP_LOCAL_PROXY"):
        if name in os.environ:
            raw = os.environ.get(name, "").strip()
            if raw.lower() in {"", "0", "off", "none", "direct", "disabled"}:
                return ""
            proxy = normalize_pre_proxy_url(raw)
            register_proxy_for_redaction(proxy)
            return proxy
    raw = ""
    return normalize_pre_proxy_url(raw) if raw else ""


def load_proxy_file(path: Path) -> list[str]:
    proxies: list[str] = []
    if not path.exists():
        return proxies
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            register_proxy_for_redaction(line)
            proxy = normalize_proxy_url(line)
            if proxy:
                proxies.append(proxy)
    random.shuffle(proxies)
    return proxies


def proxy_seed_file() -> Path:
    raw = (
        os.environ.get("UPI_PROXY_SEED_FILE", "").strip()
        or os.environ.get("PP_PROXY_SEED_FILE", "").strip()
    )
    return Path(raw).expanduser() if raw else SCRIPT_DIR / "proxy_seeds.txt"


def is_direct_remove_proxy_error(reason: str) -> bool:
    text = str(reason or "").lower()
    return any(
        marker in text
        for marker in (
            "proxy authentication",
            "proxy auth",
            "resolve proxy",
            "could not resolve proxy",
            "invalid proxy",
            "malformed proxy",
            "unsupported proxy",
            "http 407",
            "status 407",
        )
    )


def is_proxy_health_failure(reason: str) -> bool:
    text = str(reason or "").lower()
    return any(
        marker in text
        for marker in (
            "目标站不可达",
            "proxy-server",
            "connection reset",
            "recv failure",
            "timed out",
            "timeout",
            "connect tunnel failed",
            "proxy connect aborted",
            "proxy tunneling",
            "proxy handshake",
            "connection refused",
            "ssl connect",
            "tls connect",
            "curl: (28)",
            "curl: (35)",
            "curl: (56)",
            "http_502",
            "http_503",
            "http_504",
            # ---- 协议 / 认证 / 地址解析类 ----
            # 以前这几类漏判会走进 record_proxy_result(..., False)，被当成"出口失败"
            # 累计到 fail 次数里，把出口健康度统计污染掉；而它们的真实原因是
            # 「协议选错了」或「代理本身连不上」，属于出口可用性问题，应当归类为
            # 出口故障（用于换出口重试 + 健康计数），而不是当成正常失败。
            "代理认证失败",
            "proxy authentication",
            "proxy auth",
            "socks5 authentication",
            "authentication failed",
            "authentication required",
            "http 407",
            "status 407",
            "curl: (5)",   # CURLE_COULDNT_RESOLVE_PROXY
            "curl: (6)",   # CURLE_COULDNT_RESOLVE_HOST
            "curl: (7)",   # CURLE_COULDNT_CONNECT
            "curl: (97)",  # CURLE_PROXY（SOCKS 握手失败等）
            "could not resolve proxy",
            "couldn't resolve proxy",
            "failed to connect to proxy",
            "unsupported proxy",
            "unsupported scheme",
            "无法解析代理",
            "不支持代理协议",
            "不支持代理",
        )
    )


def remove_failed_proxies(group: str, failures: list[tuple[str, str]]) -> int:
    if not failures or not env_bool("UPI_PROXY_REMOVE_FAILED", True):
        return 0
    for proxy, _reason in failures:
        register_proxy_for_redaction(proxy)
    path = proxy_seed_file()
    if not path.is_file():
        return 0
    reasons = {proxy_chain_key(proxy): reason for proxy, reason in failures if proxy_chain_key(proxy)}
    if not reasons:
        return 0
    with _proxy_file_lock:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        removed = [line for line in lines if proxy_chain_key(line) in reasons]
        if not removed:
            return 0
        kept = [line for line in lines if proxy_chain_key(line) not in reasons]
        quarantine = RUNTIME_DIR / "removed_proxies.jsonl"
        with open(quarantine, "a", encoding="utf-8") as f:
            for line in removed:
                chain_key = proxy_chain_key(line)
                f.write(
                    json.dumps(
                        {
                            "time": int(time.time()),
                            "group": group,
                            "proxy": proxy_label(line.strip()),
                            "reason": redact_log_text(str(reasons.get(chain_key) or ""))[:300],
                            "source": path.name,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        temp_path = path.with_name(f".{path.name}.tmp")
        temp_path.write_text("".join(kept), encoding="utf-8")
        os.replace(temp_path, path)
        return len(removed)


def remove_failed_proxy(group: str, proxy: str, reason: str) -> bool:
    return remove_failed_proxies(group, [(proxy, reason)]) > 0


def unique_proxy_seeds(proxy_seeds: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    duplicates = 0
    for proxy_seed in proxy_seeds:
        chain_key = proxy_chain_key(proxy_seed)
        if not chain_key or chain_key in seen:
            duplicates += 1
            continue
        seen.add(chain_key)
        unique.append(proxy_seed)
    if duplicates:
        log(f"代理 Seed 去重: 忽略相同 sticky session {duplicates} 条", "[WARN] ")
    return unique


_PRIVATE_EXIT_RE = re.compile(
    r"(?i)(?:^|[@:/\[\s])("
    r"127\.\d+\.\d+\.\d+|"
    r"0\.0\.0\.0|"
    r"10\.\d+\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+|"
    r"169\.254\.\d+\.\d+|"
    r"localhost|\[::1\]"
    r")"
)


def is_private_exit_proxy(proxy: str) -> bool:
    """出口池里出现回环/内网地址 → 典型"环境污染"（本机 Clash/V2Ray 残留）。

    这类条目只在本机开着代理时才"能用"，而且一旦命中就会把请求送去**另一个国家**
    的出口，与账号/账单地区不一致，是 UPI 这类链路被风控的常见来源。服务器上
    没有本机代理时它又会直接 ConnectionRefused，让任务以「网络错误」草草结束。
    注意：``UPI_PRE_PROXY`` 是**有意配置的链路前置代理**，不走这个判断。
    """
    value = unquote(normalize_proxy_url(proxy))
    if not value:
        return False
    parsed = urlsplit(value)
    host = (parsed.hostname or "").strip()
    if not host:
        # 形如 host:port:user:pass 的裸写法，取第一段再判
        host = value.split(":", 1)[0]
    return bool(_PRIVATE_EXIT_RE.search(host)) or _PRIVATE_EXIT_RE.search(value) is not None


def strip_private_exit_seeds(proxy_seeds: list[str], *, stage: str = "出口池") -> list[str]:
    """剔除出口池里的回环/内网条目，并明确告知管理员，避免静默走错出口。"""
    kept: list[str] = []
    dropped: list[str] = []
    for proxy_seed in proxy_seeds:
        if is_private_exit_proxy(proxy_seed):
            dropped.append(proxy_seed)
            continue
        kept.append(proxy_seed)
    if dropped:
        samples = ", ".join(proxy_label(item) for item in dropped[:3])
        log(
            f"{stage} 检测到 {len(dropped)} 条本机/内网代理（如 127.0.0.1:7890 的 Clash/V2Ray 残留），"
            f"已剔除：{samples}。这类出口只会把请求送去别的国家，"
            "或在本机没开代理时直接连不上；如需链路前置代理请用 UPI_PRE_PROXY。",
            "[WARN] ",
        )
    return kept


# 各家代理的粘性会话标记写法：711proxy 用 -session-，1024proxy 用 -sid-，
# proxy001 用 _ssid_。统一按「分隔符 + 关键词」匹配，避免误判 host 里的 session。
_STICKY_SELECTOR_RE = re.compile(
    r"(?i)(?:^|[-_])(?:ssid|session|sessauto|sess|sid)(?:[-_=]|$)"
)


def looks_sticky_exit(proxy: str) -> bool:
    """出口是否带会话粘连标记（``-sid-``/``-session-`` 等）。

    UPI 0 元链要连续十几个请求落在**同一条隧道**上，轮换出口会在中途换 IP，
    让上游看到「同一账单/设备跨 IP 跳变」，这是抬升 block 概率的常见原因。
    这里只做判断与告警，不改写用户配置。
    """
    value = unquote(normalize_proxy_url(proxy))
    if not value:
        return False
    # 只在用户名/查询串里找选择器，避免把 host 里的 "session" 误判成粘性标记。
    parsed = urlsplit(value)
    haystack = " ".join(
        part for part in (parsed.username or "", parsed.query or "", parsed.path or "") if part
    ) or value
    return bool(_STICKY_SELECTOR_RE.search(haystack))


def warn_non_sticky_pool(proxy_seeds: list[str], *, stage: str = "UPI 出口池") -> int:
    """整池都没有粘连标记时告警，避免用轮换出口打多步链路。"""
    if not proxy_seeds:
        return 0
    sticky_count = sum(1 for item in proxy_seeds if looks_sticky_exit(item))
    if sticky_count:
        return sticky_count
    log(
        f"{stage} 共 {len(proxy_seeds)} 条，均未带会话粘连标记（-sid-/-session-）。"
        "UPI 0 元链要连续十余个请求复用同一出口，轮换出口会在中途换 IP，"
        "明显抬高风控概率；建议按其它渠道的做法为每条出口加 sticky session，"
        "或降低该池并发。",
        "[WARN] ",
    )
    return 0


def warn_socks5_scheme_preference() -> bool:
    """裸 socks5 配法提示统一用 socks5h（只告警，不改配置）。"""
    hint = socks_scheme_hint()
    if not hint:
        return False
    log(
        "出口协议：当前使用 socks5（本地解析 DNS）。同一出口下 socks5 与 socks5h "
        "实测落地 IP 一致，但 socks5h 把 DNS 也交给代理端，不受本地 DNS 影响，"
        "排查出口问题时更干净；建议统一改为 socks5h。",
        "[WARN] ",
    )
    return True


def order_proxy_seeds_by_exit_score(proxy_seeds: list[str]) -> list[str]:
    """按出口 ASN 画像把出口重排（默认关闭，纯排序不改池子）。

    该函数只在开关 ``UPI_ASN_SCORING`` 打开时生效，且仅在**连通性/冷却允许的
    候选范围内**做稳定重排——不动用池子、不联网、不剔除任何出口。缓存缺失的
    出口按中性分处理，因此对现有行为零影响。

    打分依赖 ``egress_cache.json``（Seed → 真实出口 IP）与 ``exit_asn_cache.json``
    （IP → ASN 画像）。这两份缓存由 ``scripts/warm_exit_asn.py`` 预热生成，
    **换池后必须重跑**，否则命中率归零、打分静默失效（所有出口都是 unknown 0 分）。
    命中率过低时这里会明确告警，不再静默返回。
    """
    try:
        from .exit_scoring import order_by_exit_score, scoring_enabled, build_ip_map
    except ImportError:
        return proxy_seeds
    if not scoring_enabled() or len(proxy_seeds) < 2:
        return proxy_seeds
    try:
        ip_of = build_ip_map(proxy_seeds)
        # 缓存是「换池后必须重跑预热」的产物；命中率塌下去时打分等于没生效，
        # 静默返回会让管理员误以为 asn_scoring=true 正在按 ASN 挑出口。
        # 用 50% 阈值而不是「少一条就报」：预热时个别 Seed 探测超时属正常
        # （4999 条里通常只剩几条无映射），那不该刷屏告警。
        if len(ip_of) * 2 < len(proxy_seeds):
            log(
                f"出口 ASN 打分缓存命中率过低：{len(ip_of)}/{len(proxy_seeds)} 条 Seed "
                "能映射到已知出口 IP（<50%）。打分依赖 egress_cache.json + "
                "exit_asn_cache.json，换过代理池后必须重跑 `python scripts/warm_exit_asn.py "
                "--pool-key alt_upi` 重新预热，否则本次排序对未命中的 Seed 不起作用"
                "（它们都按 unknown 中性分处理）。",
                "[WARN] ",
            )
        if not ip_of:
            return proxy_seeds
        ordered, counts = order_by_exit_score(proxy_seeds, ip_of=ip_of)
        log(
            "出口 ASN 打分排序："
            f"移动段={counts.get('mobile', 0)}，宽带={counts.get('broadband', 0)}，"
            f"未知={counts.get('unknown', 0)}（非移动段已前置）"
        )
        return ordered
    except Exception as exc:  # noqa: BLE001 - 打分绝不能阻断提链
        log(f"出口 ASN 打分跳过（{str(exc)[:120]}）", "[WARN] ")
        return proxy_seeds


def load_proxy_seeds() -> list[str]:
    path = proxy_seed_file()
    if not path.is_file():
        raise RuntimeError("代理 Seed 文件不存在")
    raw_seeds = unique_proxy_seeds(load_proxy_file(path))
    proxy_seeds = strip_private_exit_seeds(raw_seeds)
    if not proxy_seeds:
        if raw_seeds:
            raise RuntimeError(
                "代理 Seed 全为本机/内网代理（例如 127.0.0.1:7890 的 Clash/V2Ray 残留），"
                "已全部剔除；请在后台配置真实的境外出口池，"
                "或改用「后端系统代理」配置链路前置代理"
            )
        raise RuntimeError("代理 Seed 为空")
    prune_proxy_seed_state(proxy_seeds)
    proxy_seeds = order_proxy_group("seed", proxy_seeds)
    if not proxy_seeds:
        raise RuntimeError("代理 Seed 已全部处于失败冷却")
    proxy_seeds = order_proxy_seeds_by_exit_score(proxy_seeds)
    log(f"加载代理 Seed {len(proxy_seeds)} 条")
    warn_non_sticky_pool(proxy_seeds)
    warn_dns_resolution_scheme()
    log(
        "严格代理策略: 每轮取一条 seed，派生 "
        f"{UPI_BOOTSTRAP_COUNTRY} Checkout → {' → '.join(UPI_PROMOTION_COUNTRIES)} checkout/update → "
        f"{UPI_PROVIDER_COUNTRY} Stripe/UPI/approve"
    )
    log(f"裸代理默认协议: {default_proxy_scheme()}://")
    log(f"本机前置代理: {proxy_short(pre_proxy_url())}")
    return proxy_seeds


def new_session(
    proxy: str = "",
    use_pre_proxy: bool = True,
    fingerprint_profile: dict[str, Any] | None = None,
    transport: str = "",
) -> Any:
    pre_proxy = pre_proxy_url() if use_pre_proxy else ""
    register_proxy_for_redaction(pre_proxy)
    mode = str(
        transport
        or os.environ.get("UPI_TRANSPORT")
        or os.environ.get("UPI_BROWSER_MODE")
        or "protocol"
    ).strip().lower()
    if mode not in {
        "protocol",
        "curl",
        "http",
        "headless",
        "playwright",
        "chromium",
    }:
        raise RuntimeError(
            f"{UPI_HEADLESS_BROWSER_UNAVAILABLE}: "
            f"UPI_TRANSPORT={mode or '-'} 无效，可用 protocol/headless"
        )
    if mode in {"headless", "playwright", "chromium"}:
        session = PlaywrightBrowserSession(
            proxy=proxy,
            pre_proxy=pre_proxy,
            fingerprint_profile=fingerprint_profile,
            timeout_ms=CHATGPT_TIMEOUT * 1000,
        )
    else:
        session = ProtocolHttpSession(
            proxy=proxy,
            pre_proxy=pre_proxy,
            fingerprint_profile=fingerprint_profile,
            timeout_ms=CHATGPT_TIMEOUT * 1000,
        )
    if proxy:
        set_proxy(session, proxy)
    runtime = getattr(session, "transport_runtime", {})
    tls_detail = ""
    if isinstance(runtime, dict) and runtime:
        requested_tls = str(runtime.get("requested_tls") or "-")
        effective_tls = str(runtime.get("effective_tls") or "-")
        curl_version = str(runtime.get("curl_cffi") or "-")
        tls_detail = (
            f"；tls=requested:{requested_tls}/effective:{effective_tls}"
            f"；curl_cffi={curl_version}"
        )
    log(
        (
            "UPI 使用真实无头指纹浏览器："
            if getattr(session, "is_browser_backed", False)
            else "UPI 使用指纹 HTTP 协议会话（无浏览器）："
        )
        + f"transport={getattr(session, 'transport_name', mode)}；"
        + f"proxy={proxy_label(proxy)}；"
        + f"fingerprint={_fingerprint_value(fingerprint_profile, 'fingerprint_id', default='-')}"
        + tls_detail
    )
    return session


def prune_dump_files(keep: int = 0) -> int:
    """限制 ``dumps/`` 体量，避免长期运行把磁盘和目录 inode 堆成"环境污染"。

    默认保留最新的 ``UPI_DUMP_KEEP``（默认 2000）个抓包文件；每写入 100 份
    触发一次，开销摊薄后可以忽略。只删自己写出的 ``*.txt``，不做递归删除。
    """
    limit = int(keep or env_int("UPI_DUMP_KEEP", 2000, minimum=100))
    try:
        entries = [item for item in DUMP_DIR.iterdir() if item.is_file() and item.suffix == ".txt"]
    except OSError:
        return 0
    if len(entries) <= limit:
        return 0
    try:
        entries.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    except OSError:
        return 0
    removed = 0
    for item in entries[limit:]:
        try:
            item.unlink()
            removed += 1
        except OSError:
            continue
    if removed:
        log(f"抓包目录已清理 {removed} 个历史 dump（保留最新 {limit} 个）")
    return removed


def _redact_text(text: str, limit: int | None = None) -> str:
    text = text or ""
    text = re.sub(r"(Bearer\s+)[A-Za-z0-9._=-]+", r"\1***", text)
    text = re.sub(r"(__Secure-next-auth\.session-token=)[^;\\s]+", r"\1***", text)
    text = re.sub(r"(accessToken|access_token|sessionToken|token)(['\"]?\s*[:=]\s*['\"])[^'\"]+", r"\1\2***", text)
    text = redact_log_text(text)
    if limit is None:
        limit = env_int("UPI_DUMP_LIMIT", 6000, minimum=500)
    return text[:limit]


def dump_http(
    response: requests.Response | None,
    stage: str,
    request_body: Any = None,
    request_method: str = "",
    request_url: str = "",
    force: bool = False,
) -> None:
    if not force and not env_bool("UPI_DUMP", False):
        return
    global _dump_counter
    with _dump_lock:
        _dump_counter += 1
        name = f"{time.strftime('%Y%m%d-%H%M%S')}_{_dump_counter:04d}_{stage}.txt"
        should_prune = _dump_counter % 100 == 0
    if should_prune:
        prune_dump_files()
    path = DUMP_DIR / re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
    lines = [
        f"stage: {stage}",
        f"request: {request_method} {request_url}",
        "",
        "request_body:",
        _redact_text(json.dumps(request_body, ensure_ascii=False, indent=2) if request_body is not None else ""),
        "",
    ]
    if response is not None:
        lines.extend(
            [
                f"status: {response.status_code}",
                f"url: {response.url}",
                "",
                "response:",
                _redact_text(response.text),
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def token_key_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def find_named_token(payload: Any, aliases: tuple[str, ...]) -> str:
    wanted = {token_key_name(item) for item in aliases}
    if isinstance(payload, dict):
        cookie_name = token_key_name(payload.get("name") or payload.get("key"))
        if cookie_name in wanted:
            for value_key in ("value", "token", "content"):
                value = str(payload.get(value_key) or "").strip()
                if value:
                    return value
        for key, value in payload.items():
            if token_key_name(key) in wanted and isinstance(value, (str, int, float)):
                found = str(value).strip()
                if found:
                    return found
        for value in payload.values():
            found = find_named_token(value, aliases)
            if found:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = find_named_token(item, aliases)
            if found:
                return found
    return ""


def collect_strings(payload: Any, result: list[str] | None = None) -> list[str]:
    values = result if result is not None else []
    if isinstance(payload, str):
        values.append(payload)
    elif isinstance(payload, dict):
        for value in payload.values():
            collect_strings(value, values)
    elif isinstance(payload, list):
        for item in payload:
            collect_strings(item, values)
    return values


def find_session_cookie(payload: Any) -> str:
    for value in collect_strings(payload):
        match = re.search(r"(?:^|[;\s])__Secure-next-auth\.session-token=([^;\s]+)", value)
        if match:
            return unquote(match.group(1))
    return ""


def normalize_token(raw: str) -> tuple[str, str]:
    text = str(raw or "").strip()
    if not text:
        return "", ""
    session_token = ""
    if text.lower().startswith("bearer "):
        text = text.split(None, 1)[1].strip()
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
            access_token = find_named_token(
                data,
                (
                    "accessToken",
                    "access_token",
                    "token",
                    "bearerToken",
                    "bearer_token",
                    "jwt",
                ),
            )
            session_token = find_named_token(
                data,
                (
                    "sessionToken",
                    "session_token",
                    "nextAuthSessionToken",
                    "next_auth_session_token",
                    "__Secure-next-auth.session-token",
                    "secureNextAuthSessionToken",
                ),
            ) or find_session_cookie(data)
            text = access_token
        except json.JSONDecodeError:
            return "", ""
    return text, session_token


def decode_token_file(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "utf-8", "ascii"):
        try:
            return raw.decode(enc).strip()
        except UnicodeError:
            continue
    return raw.decode("utf-8", errors="ignore").strip()


def token_entries_from_text(text: str) -> list[str]:
    """Return candidate token entries from a one-token-per-line file."""
    entries: list[str] = []
    whole = str(text or "").strip()
    if whole.startswith("{") or whole.startswith("["):
        entries.append(whole)
    for line in str(text or "").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        normalized = item.rstrip(",").strip()
        if normalized in {"{", "}", "[", "]"}:
            continue
        if re.match(r"""^["']?[\w .:/-]{1,80}["']?\s*:""", normalized):
            continue
        if len(normalized) >= 2 and normalized[0] in {"'", '"'} and normalized[-1] == normalized[0]:
            quoted_value = ""
            try:
                quoted_value = json.loads(normalized) if normalized[0] == '"' else normalized[1:-1]
            except json.JSONDecodeError:
                quoted_value = ""
            if quoted_value.lower().startswith("bearer ") or re.match(r"^\S{10,}$", quoted_value):
                item = quoted_value
            else:
                continue
        entries.append(item)
    return list(dict.fromkeys(entries))


def first_token_from_text(text: str) -> tuple[str, str]:
    for entry in token_entries_from_text(text):
        token, session_token = normalize_token(entry)
        if token:
            return token, session_token
    return "", ""


def load_token() -> tuple[str, str]:
    for env_name in ("PP_TOKEN", "UPI_TOKEN"):
        value = os.environ.get(env_name, "").strip()
        if value:
            log(f"使用环境变量 {env_name}")
            token, session_token = normalize_token(value)
            env_session = os.environ.get("PP_SESSION_TOKEN", "").strip()
            if env_session or session_token:
                log("已加载 sessionToken cookie")
            return token, env_session or session_token

    candidates = [SCRIPT_DIR / "token.txt"]
    for path in candidates:
        if not path.exists():
            continue
        text = decode_token_file(path.read_bytes())
        if text:
            log("使用 token 文件")
            token, session_token = first_token_from_text(text)
            env_session = os.environ.get("PP_SESSION_TOKEN", "").strip()
            if env_session or session_token:
                log("已加载 sessionToken cookie")
            return token, env_session or session_token

    token = input("请输入 access_token: ").strip()
    session_token = os.environ.get("PP_SESSION_TOKEN", "").strip()
    token, parsed_session = normalize_token(token)
    return token, session_token or parsed_session


def build_chatgpt_session(
    access_token: str,
    device_id: str,
    proxy: str,
    session_token: str = "",
    fingerprint_profile: dict[str, Any] | None = None,
) -> requests.Session:
    fingerprint = dict(fingerprint_profile or {}) if isinstance(fingerprint_profile, dict) else {}
    device_id = device_id or _fingerprint_value(fingerprint, "device_id") or str(uuid.uuid4())
    session = new_session(proxy, fingerprint_profile=fingerprint)
    cookie = f"oai-did={device_id}"
    if session_token:
        cookie += f"; __Secure-next-auth.session-token={session_token}"
    user_agent = _fingerprint_value(fingerprint, "ua", "user_agent", default=DEFAULT_USER_AGENT)
    ua_lower = str(user_agent or "").lower()
    omit_ua_ch = (
        "firefox/" in ua_lower
        or "iphone" in ua_lower
        or str(fingerprint.get("browser") or "").lower() in {"firefox", "safari"}
    )
    accept_language = _fingerprint_value(
        fingerprint,
        "accept_language",
        "locale",
        default=payment_accept_language(),
    )
    sec_ch_ua = _fingerprint_value(
        fingerprint,
        "sec_ch_ua",
        default='"Safari";v="17", "Not.A/Brand";v="8"',
    )
    sec_ch_ua_platform = _fingerprint_value(
        fingerprint,
        "sec_ch_ua_platform",
        "platform",
        default='"macOS"',
    )
    if omit_ua_ch:
        sec_ch_ua = ""
        sec_ch_ua_platform = ""
    if sec_ch_ua_platform and not sec_ch_ua_platform.startswith('"'):
        sec_ch_ua_platform = f'"{sec_ch_ua_platform}"'
    account_id = ""
    try:
        from ...session_login import account_context_from_access_token as _upi_account_context
    except ImportError:  # pragma: no cover - 直跑脚本兜底
        try:
            from standalone_core.session_login import (  # type: ignore
                account_context_from_access_token as _upi_account_context,
            )
        except Exception:
            _upi_account_context = None
    if _upi_account_context is not None:
        try:
            account_id, _upi_email = _upi_account_context(access_token)
        except Exception:
            account_id = ""
    session_id_value = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"upi-oai-session:{access_token}:{device_id}")
    )
    session.headers.update(
        {
            "User-Agent": user_agent,
            "Accept": "*/*",
            "Accept-Language": accept_language,
            "Authorization": f"Bearer {access_token}",
            "Origin": "https://chatgpt.com",
            "Referer": "https://chatgpt.com/",
            "Content-Type": "application/json",
            "oai-device-id": device_id,
            "oai-language": _fingerprint_value(
                fingerprint,
                "oai_language",
                "language",
                default=payment_browser_locale(),
            ),
            "oai-session-id": session_id_value,
            "oai-client-version": CHATGPT_CLIENT_VERSION,
            "oai-client-build-number": CHATGPT_CLIENT_BUILD_NUMBER,
            "sec-ch-ua": sec_ch_ua,
            "sec-ch-ua-mobile": _fingerprint_value(fingerprint, "mobile", default="?0"),
            "sec-ch-ua-platform": sec_ch_ua_platform,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "Cookie": cookie,
        }
    )
    if account_id:
        session.headers["chatgpt-account-id"] = account_id
    if omit_ua_ch:
        for key in ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"):
            session.headers.pop(key, None)
    else:
        for key in ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"):
            if not str(session.headers.get(key) or "").strip():
                session.headers.pop(key, None)
    if not omit_ua_ch:
        for source_key, header_key in (
            ("arch", "sec-ch-ua-arch"),
            ("bitness", "sec-ch-ua-bitness"),
            ("sec_ch_ua_full_version_list", "sec-ch-ua-full-version-list"),
            ("platform_version", "sec-ch-ua-platform-version"),
        ):
            value = _fingerprint_value(fingerprint, source_key)
            if value:
                if header_key != "sec-ch-ua-full-version-list" and not value.startswith('"'):
                    value = f'"{value}"'
                session.headers[header_key] = value
    return session


def checkout_response_has_promo(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    for key in (
        "scheduled_discount_preview",
        "immediate_discount_settings",
        "promo_campaign",
        "promo_credit_grant",
    ):
        value = payload.get(key)
        if value not in (None, "", [], {}):
            return True
    return False


def checkout_response_has_trial(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("one_click_trial_eligible") is True:
        return True
    subscription_data = payload.get("subscription_data")
    if isinstance(subscription_data, dict) and int(subscription_data.get("trial_period_days") or 0) > 0:
        return True
    for key in ("trial_period_days", "trial_end"):
        value = payload.get(key)
        if value not in (None, "", 0, "0", False):
            return True
    return False


def require_upi_payment_methods(payload: Any, stage: str) -> list[str]:
    raw_methods = first_value_by_key(payload, "payment_method_types")
    if not isinstance(raw_methods, list):
        raise RuntimeError(
            f"{UPI_METHOD_UNAVAILABLE_ERROR}: {stage}: payment_method_types missing"
        )
    methods = [
        str(item).strip().lower()
        for item in raw_methods
        if str(item or "").strip()
    ]
    if "upi" not in methods:
        raise RuntimeError(
            f"{UPI_METHOD_UNAVAILABLE_ERROR}: {stage}: payment_method_types={methods}"
        )
    return list(dict.fromkeys(methods))


def payment_method_types_or_empty(payload: Any) -> list[str]:
    """新版 Checkout/update 契约在 Stripe init 前不会返回支付方式列表。"""
    raw_methods = first_value_by_key(payload, "payment_method_types")
    if not isinstance(raw_methods, list):
        return []
    return [
        str(item).strip().lower()
        for item in raw_methods
        if str(item or "").strip()
    ]


def payment_evidence(payload: Any) -> dict[str, Any]:
    """Keep only safe, non-sensitive promo/trial evidence for task results."""
    if not isinstance(payload, dict):
        return {"promo_detected": False, "trial_detected": False, "promo_keys": [], "trial_keys": []}
    promo_keys = [
        key
        for key in (
            "scheduled_discount_preview",
            "immediate_discount_settings",
            "promo_campaign",
            "promo_credit_grant",
        )
        if payload.get(key) not in (None, "", [], {})
    ]
    trial_keys = [
        key
        for key in ("one_click_trial_eligible", "trial_period_days", "trial_end", "subscription_data")
        if payload.get(key) not in (None, "", [], {}, 0, "0", False)
    ]
    return {
        "promo_detected": bool(promo_keys),
        "trial_detected": bool(trial_keys),
        "promo_keys": promo_keys,
        "trial_keys": trial_keys,
    }


def _session_bearer_token(session: Any) -> str:
    headers = getattr(session, "headers", {}) or {}
    value = str(headers.get("Authorization") or headers.get("authorization") or "").strip()
    if value.lower().startswith("bearer "):
        return value.split(None, 1)[1].strip()
    return ""


def upi_sentinel_headers(
    chatgpt: Any,
    *,
    flow: str = "chatgpt_checkout",
    page_url: str = "https://chatgpt.com/",
) -> dict[str, str]:
    """Mint OpenAI Sentinel headers for a browser-backed ChatGPT API request.

    OpenAI Checkout classifies a bare Authorization-only POST as detached
    automation and answers ``unusual activity`` (observed as HTTP 400) even
    when the access token is valid and ``/backend-api/me`` returns 200.
    Sending a Sentinel token minted on the same device/proxy/session makes
    the Checkout call match the signed-in web flow (verified HTTP 200).
    """
    if not env_bool("UPI_SENTINEL", True):
        return {}
    headers = getattr(chatgpt, "headers", {}) or {}
    if headers.get("openai-sentinel-token"):
        return {}
    access_token = _session_bearer_token(chatgpt)
    device_id = str(
        headers.get("oai-device-id")
        or headers.get("OAI-Device-Id")
        or ""
    ).strip()
    user_agent = str(headers.get("User-Agent") or DEFAULT_USER_AGENT).strip()
    if not access_token or not device_id:
        raise RuntimeError(
            "UPI_SENTINEL_UNAVAILABLE: 会话缺少 Authorization Bearer 或 oai-device-id"
        )
    try:
        from ...gcash_extract import build_sentinel_token
    except ImportError:  # pragma: no cover - 直跑脚本兜底
        from standalone_core.gcash_extract import build_sentinel_token  # type: ignore
    profile = getattr(chatgpt, "browser_profile", {})
    profile = profile if isinstance(profile, dict) else {}
    effective_tls = str(getattr(chatgpt, "effective_tls_impersonate", "") or "").strip()
    tls_impersonate = effective_tls or _fingerprint_value(
        profile,
        "tls_impersonate",
        "tls",
        default="chrome136",
    )
    sentinel_so_token = ""
    main_token = ""
    try:
        main_token = build_sentinel_token(
            access_token,
            device_id,
            user_agent,
            chatgpt,
            flow=flow,
            page_url=page_url,
            language=payment_browser_locale(),
            timezone=payment_browser_timezone(),
            cores=8,
            tls_impersonate=tls_impersonate,
        )
        sentinel_so_token = str(getattr(chatgpt, "_gcash_sentinel_so_token", "") or "")
        sentinel_mode = str(getattr(chatgpt, "_gcash_sentinel_mode", "") or "sdk")
        log(
            "UPI Sentinel 传输已与主协议会话对齐："
            f"transport=curl-cffi；tls={tls_impersonate}；mode={sentinel_mode}"
        )
    except Exception as exc:
        if env_bool("UPI_SENTINEL_REQUIRED", True):
            raise RuntimeError(
                f"UPI_SENTINEL_UNAVAILABLE: Sentinel 生成失败: {str(exc)[:300]}"
            ) from exc
        log(f"UPI Sentinel 生成失败，继续提交以保留上游错误: {str(exc)[:200]}", "[WARN] ")
        return {}
    result: dict[str, str] = {}
    if main_token:
        result["openai-sentinel-token"] = str(main_token)
        result["OpenAI-Sentinel-Token"] = str(main_token)
    so_token = sentinel_so_token
    if so_token:
        result["openai-sentinel-so-token"] = so_token
        result["OpenAI-Sentinel-SO-Token"] = so_token
    if not result:
        if env_bool("UPI_SENTINEL_REQUIRED", True):
            raise RuntimeError("UPI_SENTINEL_UNAVAILABLE: Sentinel 未返回 token")
        log("UPI Sentinel 未返回 token，继续提交以保留上游错误", "[WARN] ")
    return result


def ensure_upi_sentinel(
    chatgpt: Any,
    *,
    flow: str = "chatgpt_checkout",
    page_url: str = "https://chatgpt.com/",
) -> None:
    headers = getattr(chatgpt, "headers", {}) or {}
    if headers.get("openai-sentinel-token"):
        return
    sentinel_headers = upi_sentinel_headers(chatgpt, flow=flow, page_url=page_url)
    if sentinel_headers:
        try:
            chatgpt.headers.update(sentinel_headers)
        except Exception:
            pass


def checkout_sentinel_ping(chatgpt: requests.Session) -> None:
    """Pre-warm the Sentinel context right before checkout, like the web UI."""
    try:
        resp = chatgpt.post(
            "https://chatgpt.com/backend-api/sentinel/ping",
            json={},
            headers={
                "Referer": "https://chatgpt.com/",
                "x-openai-target-path": "/backend-api/sentinel/ping",
                "x-openai-target-route": "/backend-api/sentinel/ping",
            },
            timeout=CHATGPT_TIMEOUT,
        )
        dump_http(
            resp,
            "checkout_sentinel_ping",
            {},
            "POST",
            "https://chatgpt.com/backend-api/sentinel/ping",
            force=env_bool("UPI_DUMP_WARMUP", False),
        )
    except Exception as exc:  # noqa: BLE001 - warmup must never block checkout
        log(f"checkout Sentinel 预热异常：{exc}", "[WARN] ")


def checkout_analytics_track(chatgpt: requests.Session, checkout_referer: str) -> None:
    """Emit the web UI's Segment track event before checkout (best effort)."""
    headers = dict(getattr(chatgpt, "headers", {}) or {})
    device_id = str(headers.get("oai-device-id") or "")
    session_id = str(headers.get("oai-session-id") or "")
    account_id = str(headers.get("chatgpt-account-id") or "")
    client_version = str(headers.get("oai-client-version") or CHATGPT_CLIENT_VERSION)
    build_number = str(headers.get("oai-client-build-number") or CHATGPT_CLIENT_BUILD_NUMBER)
    locale = str(headers.get("oai-language") or "en-US")
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    app_version = client_version.removeprefix("prod-")
    body = {
        "timestamp": now_iso,
        "integrations": {"Segment.io": True},
        "event": "Account Pay: Payment Checkout Clicked",
        "type": "track",
        "properties": {
            "currentPlanType": "free",
            "subscriptionStatus": {
                "hasPaidSubscription": False,
                "subscriptionPlan": "chatgptfreeplan",
                "wasPaidCustomer": False,
            },
            "planType": "plus",
            "isUpgradeUiDisabled": False,
            "origin": "chat",
            "app_version": app_version,
        },
        "context": {
            "page": {
                "path": "/",
                "referrer": checkout_referer,
                "search": "/",
                "title": "ChatGPT 方案",
                "url": "https://chatgpt.com/#pricing",
                "hash": "#pricing",
            },
            "locale": locale,
            "timezone": os.environ.get("UPI_BROWSER_TIMEZONE", "Asia/Kolkata"),
            "device_id": device_id,
            "auth_status": "logged_in",
            "user_traits": {"plan_type": "free"},
        },
        "anonymousId": str(uuid.uuid4()),
        "messageId": f"ajs-next-{int(time.time() * 1000)}-{uuid.uuid4()}",
        "userId": account_id or device_id or session_id,
        "writeKey": "oai",
        "sentAt": now_iso,
    }
    try:
        resp = chatgpt.post(
            "https://chatgpt.com/ces/v1/t",
            data=json.dumps(body, ensure_ascii=False),
            headers={
                "accept": "*/*",
                "content-type": "text/plain",
                "oai-client-build-number": build_number,
                "oai-client-version": client_version,
                "Referer": checkout_referer,
                "x-openai-target-path": "/ces/v1/t",
                "x-openai-target-route": "/ces/v1/t",
            },
            timeout=CHATGPT_TIMEOUT,
        )
        dump_http(
            resp,
            "checkout_analytics_track",
            body,
            "POST",
            "https://chatgpt.com/ces/v1/t",
            force=env_bool("UPI_DUMP_WARMUP", False),
        )
    except Exception as exc:  # noqa: BLE001 - analytics must never block checkout
        log(f"checkout 分析埋点异常：{exc}", "[WARN] ")


def _zero_ineligible_until(account_id: str) -> float:
    try:
        from ...fingerprint_store import zero_ineligible_until
    except ImportError:  # pragma: no cover - direct CLI fallback
        from standalone_core.fingerprint_store import zero_ineligible_until  # type: ignore
    try:
        return float(zero_ineligible_until(account_id))
    except Exception:
        return 0.0


def _mark_zero_ineligible(account_id: str, cooldown_seconds: int = 86400) -> None:
    try:
        from ...fingerprint_store import mark_zero_ineligible
    except ImportError:  # pragma: no cover - direct CLI fallback
        from standalone_core.fingerprint_store import mark_zero_ineligible  # type: ignore
    try:
        mark_zero_ineligible(account_id, cooldown_seconds=cooldown_seconds)
    except Exception:  # noqa: BLE001 - best effort cache
        return


def checkout_zero_eligible(chatgpt: requests.Session) -> bool | None:
    """Return whether the account currently has the plus-1-month-free coupon.

    ``None`` means the probe itself failed (network/unknown), so callers should
    not block the checkout on it.
    """
    try:
        resp = chatgpt.get(
            "https://chatgpt.com/backend-api/promo_campaign/check_coupon",
            params={
                "coupon": "plus-1-month-free",
                "is_coupon_from_query_param": "true",
            },
            headers={
                "Referer": "https://chatgpt.com/",
                "Origin": "https://chatgpt.com",
                "Accept": "application/json",
                "x-openai-target-path": "/backend-api/promo_campaign/check_coupon",
                "x-openai-target-route": "/backend-api/promo_campaign/check_coupon",
            },
            timeout=CHATGPT_TIMEOUT,
        )
        if resp.status_code >= 400:
            return None
        state = str((resp.json() or {}).get("state") or "").strip().lower()
        return state == "eligible"
    except Exception:  # noqa: BLE001 - probe must never block checkout
        return None


def ensure_upi_zero_eligible(chatgpt: requests.Session, account_id: str) -> None:
    """Fast-fail a zero-amount run when the account is known ineligible."""
    account_id = str(account_id or "").strip()
    if not account_id:
        return
    now = time.time()
    until = _zero_ineligible_until(account_id)
    if until > now:
        remaining_minutes = max(0, int((until - now) // 60))
        raise RuntimeError(
            f"{UPI_ZERO_INELIGIBLE}: 账号 0 元资格负缓存生效，"
            f"冷却约 {remaining_minutes} 分钟，跳过 0 元链"
        )
    eligible = checkout_zero_eligible(chatgpt)
    if eligible is False:
        _mark_zero_ineligible(account_id)
        raise RuntimeError(
            f"{UPI_ZERO_INELIGIBLE}: 账号无 0 元试用资格"
            f"（check_coupon=not_eligible），跳过 0 元链"
        )


def create_checkout(
    chatgpt: requests.Session,
    country: str,
    *,
    promo_override: str = "",
    billing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    country = normalize_country(country)
    currency = currency_for_country(country)
    promo_mode = (
        promo_override
        or os.environ.get("PP_PROMO_MODE", "campaign")
    ).strip().lower() or "campaign"
    promo_id = os.environ.get("PP_PROMO_ID", "plus-1-month-free").strip()
    body: dict[str, Any] = {
        "entry_point": os.environ.get("PP_ENTRY_POINT", "all_plans_pricing_modal"),
        "plan_name": "chatgptplusplan",
        "billing_details": {"country": country, "currency": currency},
        "checkout_ui_mode": "custom",
    }
    if promo_mode in ("trial", "free_trial"):
        trial_days = env_int("PP_TRIAL_DAYS", 30)
        body["subscription_data"] = {"trial_period_days": trial_days}
    elif promo_mode in ("campaign", "query"):
        body["promo_campaign"] = {
            "promo_campaign_id": promo_id,
            "is_coupon_from_query_param": promo_mode == "query",
        }
    elif promo_mode == "coupon":
        body["coupon"] = promo_id
    elif promo_mode == "code":
        body["promotion_code"] = promo_id
    elif promo_mode != "off":
        log(f"未知 PP_PROMO_MODE={promo_mode!r}，已忽略", "[WARN] ")
    # MoMo aligned zero-amount strategies (trial period and/or full billing profile).
    #
    # 只在「0 元链」上注入：用户选「原价链」时必须保留正价——否则管理员把
    # UPI_ZERO_MODE 设成 trial/momo 后，即便 promo_mode=off，这里仍会补上
    # subscription_data.trial_period_days / promo_campaign，金额被压到 0，
    # 又回到 0 元人工审批链路（用户明明选了原价链却提 0 元链的根因之一）。
    if chain_requires_zero():
        apply_zero_mode_body(
            body,
            country=country,
            currency=currency,
            promo_id=promo_id,
            billing=billing,
        )
    elif zero_mode() != "campaign":
        log(
            f"提链类型=原价链：跳过 0 元策略注入（管理员 zero_mode={zero_mode()}），保留正价金额",
            "[WARN] ",
        )
    log(f"Checkout promo: mode={promo_mode}, id={promo_id}")

    # 对齐网页端：带 promo_campaign 建单时页面 Referer 是
    # https://chatgpt.com/?promo_campaign=plus-1-month-free
    checkout_referer = "https://chatgpt.com/"
    if promo_mode in {"campaign", "query", "coupon"} and promo_id:
        checkout_referer = f"https://chatgpt.com/?promo_campaign={promo_id}"
    headers = {
        "Referer": checkout_referer,
        "x-openai-target-path": "/backend-api/payments/checkout",
        "x-openai-target-route": "/backend-api/payments/checkout",
    }
    ensure_upi_sentinel(
        chatgpt,
        flow="chatgpt_checkout",
        page_url=checkout_referer,
    )
    log("UPI Checkout 使用 OpenAI Sentinel 会话上下文（页面 Referer 对齐网页端）")
    if env_bool("UPI_CHECKOUT_ANALYTICS_TRACK", False):
        checkout_analytics_track(chatgpt, checkout_referer)
    if env_bool("UPI_CHECKOUT_PING_WARMUP", True):
        checkout_sentinel_ping(chatgpt)
    resp = chatgpt.post(
        "https://chatgpt.com/backend-api/payments/checkout",
        json=body,
        headers=headers,
        timeout=CHATGPT_TIMEOUT,
    )
    dump_http(resp, "checkout", body, "POST", "https://chatgpt.com/backend-api/payments/checkout", force=resp.status_code >= 400)
    if resp.status_code >= 400:
        if is_user_already_paid_error(resp.text):
            raise RuntimeError("用户已支付: User is already paid")
        raise RuntimeError(f"checkout 创建失败 HTTP {resp.status_code}: {resp.text[:500]}")

    data = resp.json() or {}
    if (
        promo_mode == "coupon"
        and promo_id == "plus-1-month-free"
        and not checkout_response_has_promo(data)
        and env_bool("UPI_COUPON_FALLBACK_PROMO_CAMPAIGN", True)
    ):
        log("coupon 响应未显示优惠，按 promo_campaign 字符串重试", "[PROMO] ")
        fallback_body = dict(body)
        fallback_body.pop("coupon", None)
        fallback_body["promo_campaign"] = promo_id
        resp = chatgpt.post(
            "https://chatgpt.com/backend-api/payments/checkout",
            json=fallback_body,
            headers=headers,
            timeout=CHATGPT_TIMEOUT,
        )
        dump_http(
            resp,
            "checkout_promo_campaign",
            fallback_body,
            "POST",
            "https://chatgpt.com/backend-api/payments/checkout",
            force=True,
        )
        if resp.status_code >= 400:
            if is_user_already_paid_error(resp.text):
                raise RuntimeError("用户已支付: User is already paid")
            raise RuntimeError(f"checkout promo_campaign 重试失败 HTTP {resp.status_code}: {resp.text[:500]}")
        data = resp.json() or {}
        log(f"promo_campaign 重试后 promo={checkout_response_has_promo(data)}", "[PROMO] ")

    methods = payment_method_types_or_empty(data)
    if not methods:
        log(
            "Checkout 创建响应未直接返回 payment_method_types（新版契约在 Stripe init 后才返回），"
            "继续在 Bootstrap Stripe init 阶段确认 UPI 可用性",
            "[WARN] ",
        )
    cs_id = data.get("checkout_session_id") or data.get("session_id") or data.get("id")
    cs_id_value = str(cs_id or "").strip()
    if not (cs_id_value.startswith("cs_") or cs_id_value.startswith("oaics_")):
        raise RuntimeError(f"checkout 响应缺少 cs_id: {str(data)[:500]}")

    raw_pk = (
        data.get("stripe_publishable_key")
        or data.get("publishable_key")
        or data.get("publishableKey")
        or data.get("stripePublishableKey")
        or data.get("key")
        or ""
    )
    match = re.search(r"pk_live_[A-Za-z0-9]+", str(raw_pk))
    stripe_pk = match.group(0) if match else DEFAULT_STRIPE_PK
    processor_entity = str(data.get("processor_entity") or data.get("processorEntity") or "")
    checkout_provider = str(data.get("checkout_provider") or "").strip().lower()
    if not checkout_provider:
        checkout_provider = "open_ai" if cs_id_value.startswith("oaics_") else "stripe"
    provider_stats = record_checkout_provider(checkout_provider, cs_id_value)
    log(
        f"Checkout 创建成功: {cs_id} / {country} / {currency_for_country(country)} / "
        f"provider={checkout_provider} / "
        f"mode={promo_mode} / promo={checkout_response_has_promo(data)} / "
        f"trial={checkout_response_has_trial(data)}"
    )
    log(
        "Checkout 通道分流统计: "
        f"total={provider_stats['total']} "
        f"stripe={provider_stats['stripe']} "
        f"open_ai={provider_stats['open_ai']} "
        f"oaics={provider_stats['oaics']} "
        f"cs_live={provider_stats['cs_live']}"
    )
    if checkout_provider == "open_ai" or str(cs_id_value).startswith("oaics_"):
        log("★ 命中 OAICS 通道：UPI mandate_options 开关本轮生效", "[IMPORTANT] ")
    else:
        log(
            "★ 未命中 OAICS 通道（cs_live_/stripe）：mandate_options 本轮不生效，"
            "该分流由 OpenAI 服务端按账号分配，客户端不可选",
            "[IMPORTANT] ",
        )
    return {
        "cs_id": cs_id_value,
        "processor_entity": processor_entity,
        "stripe_pk": stripe_pk,
        "checkout_provider": checkout_provider,
        "customer_session_client_secret": str(
            data.get("customer_session_client_secret")
            or data.get("customerSessionClientSecret")
            or ""
        ).strip(),
        "confirm_return_url": str(data.get("confirm_return_url") or "").strip(),
        "checkout_state": data.get("checkout_state")
        if isinstance(data.get("checkout_state"), dict)
        else {},
        "tag": str(data.get("tag") or ""),
        "billing_country": country,
        "currency": currency_for_country(country),
        "payment_methods": json.dumps(methods, ensure_ascii=False),
        "promo_detected": "1" if checkout_response_has_promo(data) else "0",
        "trial_detected": "1" if checkout_response_has_trial(data) else "0",
    }


def checkout_page_url(checkout: dict[str, str]) -> str:
    processor = processor_entity_for_country(
        UPI_BOOTSTRAP_COUNTRY,
        checkout.get("processor_entity") or "",
    )
    return f"https://chatgpt.com/checkout/{processor}/{checkout['cs_id']}"


def update_checkout_promotion(
    chatgpt: requests.Session,
    checkout: dict[str, str],
    promotion_country: str,
    billing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    mode = os.environ.get("PP_PROMO_MODE", "campaign").strip().lower() or "campaign"
    promo_id = os.environ.get("PP_PROMO_ID", "plus-1-month-free").strip() or "plus-1-month-free"
    body: dict[str, Any] = {
        "checkout_session_id": checkout["cs_id"],
        "processor_entity": processor_entity_for_country(
            UPI_BOOTSTRAP_COUNTRY,
            checkout.get("processor_entity") or "",
        ),
        "plan_name": "chatgptplusplan",
        "price_interval": "month",
        "seat_quantity": 1,
    }
    if mode in {"campaign", "query", "coupon"}:
        body["promo_campaign"] = {
            "promo_campaign_id": promo_id,
            "is_coupon_from_query_param": mode == "query",
        }
    # MoMo aligned zero-amount strategies (trial period and/or full billing profile).
    # 同 create_checkout：原价链不注入 0 元策略，避免把正价链压成 0 元。
    if chain_requires_zero():
        apply_zero_mode_body(
            body,
            country=UPI_BOOTSTRAP_COUNTRY,
            currency=currency_for_country(UPI_BOOTSTRAP_COUNTRY),
            promo_id=promo_id,
            billing=billing,
        )
    url = "https://chatgpt.com/backend-api/payments/checkout/update"
    resp = chatgpt.post(
        url,
        json=body,
        headers={
            "Referer": checkout_page_url(checkout),
            "x-openai-target-path": "/backend-api/payments/checkout/update",
            "x-openai-target-route": "/backend-api/payments/checkout/update",
        },
        timeout=CHATGPT_TIMEOUT,
    )
    dump_http(resp, "checkout_promotion_update", body, "POST", url, force=resp.status_code >= 400)
    if resp.status_code >= 400:
        if is_checkout_not_active_error(resp.text):
            raise RuntimeError("checkout_not_active_session")
        raise RuntimeError(f"checkout/update 失败 HTTP {resp.status_code}: {resp.text[:500]}")
    try:
        payload = resp.json() or {}
    except Exception:
        payload = {}
    if isinstance(payload, dict) and payload.get("success") is False:
        raise RuntimeError(f"checkout/update rejected: {str(payload)[:500]}")
    methods = payment_method_types_or_empty(payload)
    if not methods:
        log(
            f"{promotion_country} checkout/update 响应未直接返回 payment_method_types，"
            "继续以随后的 Stripe init 结果为准",
            "[WARN] ",
        )
    evidence = payment_evidence(payload)
    log(
        f"{promotion_country} checkout/update 成功: "
        f"promo={promo_id if 'promo_campaign' in body else 'off'} / "
        f"methods={methods} / promo_detected={evidence['promo_detected']} / "
        f"trial_detected={evidence['trial_detected']}"
    )
    return payload


def promo_inject_pre_confirm_enabled() -> bool:
    """Admin switch: build the original-price session first, then inject the
    promo via checkout/update before Stripe confirm (variant A/B)."""
    return env_bool("UPI_PROMO_INJECT_PRE_CONFIRM", False) and env_bool("UPI_REQUIRE_ZERO", True)


def official_inline_confirmation_token_enabled() -> bool:
    """Align the successful HAR: create the ConfirmationToken with inline
    payment_method_data[type]=upi instead of creating a PM first."""
    return env_bool("UPI_OFFICIAL_INLINE_CONFIRMATION_TOKEN", False)


def oaics_mandate_options_enabled() -> bool:
    """Admin switch: inject UPI AutoPay mandate_options on the Elements session.

    外部实现（upi-git5）的实测诊断是：0 元 Checkout 走 SetupIntent 时
    ``mandate_options=missing``，支付网络会拒签该委托
    （``generic_decline`` / ``requires_payment_method``）。这里在 Elements
    session 的 deferred_intent 上补齐 UPI mandate 配置，让 Stripe 在建
    SetupIntent 时就带上 AutoPay 授权上限与到期时间。
    """
    return env_bool("UPI_OAICS_MANDATE_OPTIONS", False)


def oaics_mandate_amount() -> int:
    """Mandate 授权上限（最小货币单位）。默认按 Plus 正价 1999.00 INR。"""
    raw = os.environ.get("UPI_OAICS_MANDATE_AMOUNT", "").strip()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 0
    return value if value > 0 else 199900


def oaics_mandate_options_params(mandate_amount: int | None = None) -> dict[str, str]:
    """UPI AutoPay mandate_options，展平成 Stripe form 字段。"""
    amount = int(mandate_amount or 0) or oaics_mandate_amount()
    end_unix = int(time.time()) + 365 * 24 * 60 * 60
    return {
        "deferred_intent[payment_method_options][upi][mandate_options][amount]": str(amount),
        "deferred_intent[payment_method_options][upi][mandate_options][amount_type]": "maximum",
        "deferred_intent[payment_method_options][upi][mandate_options][description]": "Subscription payment",
        "deferred_intent[payment_method_options][upi][mandate_options][end_date]": str(end_unix),
    }


def zero_mode() -> str:
    """Admin-selectable zero-amount strategy.

    ``campaign`` (default) keeps the legacy behaviour and injects only the
    plus-1-month-free promo campaign. ``trial`` uses a real
    ``subscription_data.trial_period_days`` trial, and ``momo`` mirrors the
    100%-success MoMo flow: full billing profile + promo campaign + trial.
    """
    mode = os.environ.get("UPI_ZERO_MODE", "campaign").strip().lower() or "campaign"
    return mode if mode in {"campaign", "trial", "momo"} else "campaign"


def chain_requires_zero() -> bool:
    """当前这条链是否为「0 元链」（用户选择优先，其次管理员默认）。"""
    return env_bool("UPI_REQUIRE_ZERO", True)


def chain_kind_label() -> str:
    return "0 元链" if chain_requires_zero() else "原价链"


def original_price_zero_fallback_enabled() -> bool:
    """管理员开关：原价链被上游压成 0 元时，是否允许降级交付 0 元链。

    默认关闭——原价链命中 0 元金额时直接判失败（账号级），避免把 0 元链当成
    原价链交付。开启后按 0 元链继续交付，并在结果 meta 里标记降级。
    """
    return env_bool("UPI_ORIGINAL_PRICE_ZERO_FALLBACK", False)


def trial_period_days() -> int:
    return max(1, min(90, env_int("PP_TRIAL_DAYS", 30)))


def checkout_billing_fields(
    billing: dict[str, Any] | None,
    country: str,
    currency: str,
) -> dict[str, Any]:
    """Top-level checkout fields mirroring the visible billing form (MoMo aligned)."""
    profile = dict(billing or {})
    if not profile:
        return {}
    country = normalize_country(country)
    currency = str(currency or currency_for_country(country)).upper()
    address = {
        "line1": str(profile.get("line1") or ""),
        "line2": str(profile.get("line2") or ""),
        "city": str(profile.get("city") or ""),
        "state": str(profile.get("state") or ""),
        "postal_code": str(profile.get("postal_code") or ""),
        "country": country,
    }
    email = str(profile.get("email") or "")
    name = str(profile.get("name") or "")
    phone = str(profile.get("phone") or "")
    tax_id = str(profile.get("tax_id") or "")
    details = {
        "country": country,
        "currency": currency,
        "name": name,
        "email": email,
        "phone": phone,
        "address": address,
        "tax_id": tax_id,
    }
    return {
        "checkout_email": email,
        "customer_email": email,
        "billing_email": email,
        "billing_country": country,
        "billing_name": name,
        "customer_name": name,
        "billing_phone": phone,
        "customer_phone": phone,
        "currency": currency,
        "tax_id": tax_id,
        "billing_address": address,
        "billing_details": details,
    }


def apply_zero_mode_body(
    body: dict[str, Any],
    *,
    country: str,
    currency: str,
    promo_id: str,
    mode: str = "",
    billing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply the selected zero-amount strategy to a checkout payload."""
    resolved = str(mode or zero_mode()).strip().lower() or "campaign"
    if resolved in {"trial", "momo"}:
        body["subscription_data"] = {"trial_period_days": trial_period_days()}
    if resolved == "momo":
        if promo_id:
            body["promo_campaign"] = {
                "promo_campaign_id": promo_id,
                "is_coupon_from_query_param": False,
            }
        body.update(checkout_billing_fields(billing, country, currency))
    return body


def merge_checkout_after_promo_update(
    checkout: dict[str, Any],
    payload: dict[str, Any],
    *,
    country: str,
) -> dict[str, Any]:
    """Refresh a checkout object with the state returned by checkout/update."""
    merged = dict(checkout or {})
    if not isinstance(payload, dict):
        return merged
    checkout_state = payload.get("checkout_state")
    if isinstance(checkout_state, dict):
        merged["checkout_state"] = checkout_state
    methods = payment_method_types_or_empty(payload)
    if methods:
        merged["payment_methods"] = json.dumps(methods, ensure_ascii=False)
    merged["promo_detected"] = "1" if checkout_response_has_promo(payload) else str(merged.get("promo_detected") or "0")
    merged["trial_detected"] = "1" if checkout_response_has_trial(payload) else str(merged.get("trial_detected") or "0")
    customer_secret = str(
        payload.get("customer_session_client_secret")
        or payload.get("customerSessionClientSecret")
        or merged.get("customer_session_client_secret")
        or ""
    ).strip()
    if customer_secret:
        merged["customer_session_client_secret"] = customer_secret
    merged["billing_country"] = str(merged.get("billing_country") or country)
    return merged


def inject_promo_before_confirm(
    chatgpt: requests.Session,
    checkout: dict[str, Any],
    *,
    promotion_country: str,
    billing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Inject the campaign into an original-price checkout before confirm."""
    payload = update_checkout_promotion(chatgpt, checkout, promotion_country, billing=billing)
    updated = merge_checkout_after_promo_update(checkout, payload, country=promotion_country)
    due = _oaics_due_amount(updated)
    if due != 0:
        log(
            f"{promotion_country} confirm 前注入优惠后金额仍非 0 (due={due})，"
            "变体链路无法生成 0 元状态",
            "[WARN] ",
        )
    else:
        log(f"{promotion_country} confirm 前注入优惠成功：金额=0（minorUnits={due}）")
    return updated


def update_upi_checkout_taxes(
    chatgpt: requests.Session,
    checkout: dict[str, str],
    billing: dict[str, str],
) -> dict[str, Any]:
    url = "https://chatgpt.com/backend-api/payments/checkout/taxes"
    body = {
        "checkout_session_id": checkout["cs_id"],
        "checkout_email": billing["email"],
        "billing_country": UPI_PROVIDER_COUNTRY,
        "billing_name": billing["name"],
        "currency": currency_for_country(UPI_PROVIDER_COUNTRY),
        "tax_id": None,
        "processor_entity": processor_entity_for_country(
            UPI_BOOTSTRAP_COUNTRY,
            checkout.get("processor_entity") or "",
        ),
        "billing_address": {
            "line1": billing["line1"],
            "city": billing["city"],
            "country": UPI_PROVIDER_COUNTRY,
            "postal_code": billing["postal_code"],
        },
    }
    if billing.get("state"):
        body["billing_address"]["state"] = billing["state"]
    resp = chatgpt.post(
        url,
        json=body,
        headers={
            "Referer": checkout_page_url(checkout),
            "x-openai-target-path": "/backend-api/payments/checkout/taxes",
            "x-openai-target-route": "/backend-api/payments/checkout/taxes",
        },
        timeout=CHATGPT_TIMEOUT,
    )
    dump_http(resp, "checkout_taxes", body, "POST", url, force=resp.status_code >= 400)
    if resp.status_code >= 400:
        if is_checkout_not_active_error(resp.text):
            raise RuntimeError("checkout_not_active_session")
        raise RuntimeError(f"checkout/taxes 失败 HTTP {resp.status_code}: {resp.text[:500]}")
    try:
        payload = resp.json() or {}
    except Exception:
        payload = {}
    evidence = payment_evidence(payload)
    log(
        f"{UPI_PROVIDER_COUNTRY} checkout/taxes 同步成功: "
        f"promo_detected={evidence['promo_detected']} / trial_detected={evidence['trial_detected']}"
    )
    return payload


def stripe_fetch_origin() -> str:
    return (
        os.environ.get("UPI_STRIPE_FETCH_ORIGIN", "").strip()
        or "https://js.stripe.com/"
    )


def build_stripe_public_headers() -> dict[str, str]:
    """随机化 Stripe.js 公开请求头，降低"所有会话共用同一指纹"的关联度。

    真实网页里 Stripe.js 的版本头与机器指纹头是每次加载随机生成的；固定复用同一个
    值会让上游容易把这些请求归到一起。这里只返回公开头（不含 Authorization /
    Cookie 等会话级凭据）。
    """
    def browser_fingerprint() -> str:
        return ".".join(
            str(part)
            for part in (
                random.randint(20, 120),
                random.randint(1, 60),
                random.randint(200_000_000, 999_999_999),
                random.randint(1, 60),
                random.getrandbits(48),
            )
        )

    return {
        "stripe-js-version": (
            f"{random.randint(3, 6)}.{random.randint(0, 9)}.{random.randint(0, 9)}"
        ),
        "x-stripe-c-fingerprint": secrets.token_hex(16),
        "x-stripe-js-id": str(uuid.uuid4()),
        "x-stripe-machine-fingerprint": browser_fingerprint(),
    }


def configure_stripe_fetch_origin(stripe: Any) -> None:
    """Keep Stripe API calls on the js.stripe.com origin.

    Stripe rejects requests whose browser page origin is api.stripe.com or
    chatgpt.com with ``invalid_request_http_origin``; the official Elements
    page origin is js.stripe.com.
    """
    origin = stripe_fetch_origin()
    try:
        stripe.set_fetch_page(origin)
    except Exception:
        pass
    # 每次调用重随机 public 头（stripe-js 版本/机器指纹），避免所有会话共用同一组
    # 可被关联的指纹；strip 掉抓包里的会话级头（Authorization 等）。
    try:
        stripe.headers["Referer"] = origin
        stripe.headers["Origin"] = "https://js.stripe.com"
        public_headers = build_stripe_public_headers()
        for key, value in public_headers.items():
            stripe.headers[key] = value
    except Exception:
        pass


def stripe_init(
    cs_id: str,
    stripe_pk: str,
    proxy: str,
    fingerprint_profile: dict[str, Any] | None = None,
    device_id: str = "",
) -> dict[str, Any]:
    fingerprint = dict(fingerprint_profile or {}) if isinstance(fingerprint_profile, dict) else {}
    stripe = new_session(proxy, fingerprint_profile=fingerprint)
    stripe.headers.update(
        {
            "User-Agent": _fingerprint_value(fingerprint, "ua", "user_agent", default=random_user_agent()),
            "Accept-Language": _fingerprint_value(
                fingerprint,
                "accept_language",
                "locale",
                default=payment_accept_language(),
            ),
            # Stripe.js 是通过 js.stripe.com 的页面 cross-site fetch 到 api.stripe.com；
            # 缺 Origin/sec-fetch-* 时上游偶发 invalid_request_http_origin，
            # 表现为"随机失败"，这里对齐真实网页请求头。
            "Origin": "https://js.stripe.com",
            "Referer": "https://js.stripe.com/",
            "Accept": "application/json",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        }
    )
    configure_stripe_fetch_origin(stripe)
    stripe_js_id = str(uuid.uuid4())
    body = {
        "browser_locale": payment_browser_locale(),
        "browser_timezone": payment_browser_timezone(),
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[stripe_js_id]": stripe_js_id,
        "elements_session_client[locale]": payment_elements_locale(),
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_options_client[saved_payment_method][enable_save]": "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
    }
    url = f"https://api.stripe.com/v1/payment_pages/{cs_id}/init"
    resp = stripe.post(url, data=body, timeout=DEFAULT_TIMEOUT)
    dump_http(resp, "stripe_init", body, "POST", url, force=resp.status_code >= 400)
    if resp.status_code >= 400:
        raise RuntimeError(f"Stripe init 失败 HTTP {resp.status_code}: {resp.text[:500]}")
    payload = resp.json() or {}
    payload["client_stripe_js_id"] = stripe_js_id
    payload["_client_context"] = {
        "stripe_js_id": stripe_js_id,
        "device_id": device_id or _fingerprint_value(fingerprint, "device_id"),
        "fingerprint_id": _fingerprint_value(fingerprint, "fingerprint_id"),
    }
    return payload


def amount_from_payload(payload: Any) -> tuple[int, str]:
    if isinstance(payload, dict):
        total_summary = payload.get("total_summary")
        if isinstance(total_summary, dict) and total_summary.get("due") is not None:
            return int(total_summary.get("due") or 0), "total_summary.due"
        invoice = payload.get("invoice")
        if isinstance(invoice, dict) and invoice.get("amount_due") is not None:
            return int(invoice.get("amount_due") or 0), "invoice.amount_due"
        line_items = payload.get("line_items")
        if isinstance(line_items, list):
            total = 0
            found = False
            for item in line_items:
                if isinstance(item, dict) and item.get("amount") is not None:
                    total += int(item.get("amount") or 0)
                    found = True
            if found:
                return total, "line_items.amount"
    text = json.dumps(payload, ensure_ascii=False) if not isinstance(payload, str) else payload
    for pattern in (
        (r'"total"\s*:\s*(-?\d+)', "total"),
        (r'"amount_total"\s*:\s*(-?\d+)', "amount_total"),
        (r'"checkout_amount"\s*:\s*(-?\d+)', "checkout_amount"),
        (r'"amount"\s*:\s*(-?\d+)', "amount"),
    ):
        match = re.search(pattern[0], text)
        if match:
            return int(match.group(1)), pattern[1]
    raise RuntimeError(f"{UPI_AMOUNT_UNKNOWN_ERROR}: Stripe init 未返回可确认金额")


def build_ctx(init_payload: dict[str, Any], checkout: dict[str, str]) -> dict[str, Any]:
    client_context = init_payload.get("_client_context") if isinstance(init_payload.get("_client_context"), dict) else {}
    checkout_amount, amount_source = amount_from_payload(init_payload)
    return {
        "stripe_js_id": str(client_context.get("stripe_js_id") or init_payload.get("client_stripe_js_id") or uuid.uuid4()),
        "client_session_id": str(uuid.uuid4()),
        "guid": stripe_browser_id(),
        "muid": stripe_browser_id(),
        "sid": stripe_browser_id(),
        "elements_session_id": f"elements_session_{uuid.uuid4().hex[:11]}",
        "elements_session_config_id": str(init_payload.get("config_id") or uuid.uuid4()),
        "config_id": init_payload.get("config_id") or "",
        "init_checksum": init_payload.get("init_checksum") or "",
        "checkout_amount": checkout_amount,
        "checkout_amount_source": amount_source,
        "payment_methods": require_upi_payment_methods(init_payload, "Stripe init"),
        "locale": payment_elements_locale(),
        "currency": str(init_payload.get("currency") or checkout.get("currency") or "eur").lower(),
        "runtime_version": DEFAULT_STRIPE_RUNTIME_VERSION,
        "stripe_version": STRIPE_VERSION_FULL,
    }


def stripe_elements_session_params(ctx: dict[str, Any]) -> dict[str, str]:
    return {
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[session_id]": str(ctx.get("elements_session_id") or f"elements_session_{uuid.uuid4().hex[:11]}"),
        "elements_session_client[stripe_js_id]": str(ctx.get("stripe_js_id") or uuid.uuid4()),
        "elements_session_client[locale]": str(ctx.get("locale") or payment_elements_locale()),
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_options_client[saved_payment_method][enable_save]": "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
    }


def _billing_seed(account_id: str = "") -> int:
    """Deterministic seed for one account so retries keep the same billing."""
    key = str(
        account_id
        or os.environ.get("UPI_ACCOUNT_ID")
        or os.environ.get("UPI_EMAIL")
        or os.environ.get("PP_TOKEN")
        or ""
    ).strip()
    if not key:
        return secrets.randbits(63)
    return int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest()[:8], "big")


BILLING_POOL_VERSION = 1
_BILLING_POOL_MAX_PROBE = 20000
_BILLING_POOL_HOUSE_LIMIT = 400
_BILLING_POOL_LOCK = RLock()
_BILLING_HOUSE_SUFFIXES = ("", "", "", "A", "B", "C")


def billing_pool_path() -> Path:
    raw = os.environ.get("UPI_BILLING_POOL_FILE", "").strip()
    return Path(raw).expanduser() if raw else SCRIPT_DIR / "billing_assignments.json"


def _billing_account_key(account_id: str) -> str:
    key = str(account_id or "").strip()
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:24] if key else ""


def billing_script() -> str:
    """Billing text script: ``latin`` (default) or ``hindi`` (Devanagari)."""
    value = os.environ.get("UPI_BILLING_SCRIPT", "latin").strip().lower() or "latin"
    return value if value in {"latin", "hindi"} else "latin"


def billing_align_exit_enabled() -> bool:
    """管理员开关：账单地址尽量对齐代理出口所在城市/邦。"""
    return env_bool("UPI_BILLING_ALIGN_EXIT", False)


# 代理出口常见城市的省邦码：命中后把账单地址换到同一邦，
# 避免「出口在 Mumbai、账单在 Kolkata」这类地理不一致。
IN_CITY_STATE = {
    "mumbai": "MH",
    "thane": "MH",
    "navi mumbai": "MH",
    "pune": "MH",
    "nagpur": "MH",
    "nashik": "MH",
    "bengaluru": "KA",
    "bangalore": "KA",
    "mysuru": "KA",
    "mangaluru": "KA",
    "hubballi": "KA",
    "hyderabad": "TS",
    "secunderabad": "TS",
    "warangal": "TS",
    "visakhapatnam": "AP",
    "vijayawada": "AP",
    "guntur": "AP",
    "tirupati": "AP",
    "chennai": "TN",
    "coimbatore": "TN",
    "madurai": "TN",
    "tiruchirappalli": "TN",
    "salem": "TN",
    "kolkata": "WB",
    "howrah": "WB",
    "siliguri": "WB",
    "durgapur": "WB",
    "new delhi": "DL",
    "delhi": "DL",
    "noida": "UP",
    "ghaziabad": "UP",
    "gurugram": "HR",
    "gurgaon": "HR",
    "faridabad": "HR",
    "jaipur": "RJ",
    "jodhpur": "RJ",
    "udaipur": "RJ",
    "ahmedabad": "GJ",
    "surat": "GJ",
    "vadodara": "GJ",
    "rajkot": "GJ",
    "lucknow": "UP",
    "kanpur": "UP",
    "varanasi": "UP",
    "agra": "UP",
    "kochi": "KL",
    "cochin": "KL",
    "thiruvananthapuram": "KL",
    "kozhikode": "KL",
    "chandigarh": "CH",
    "mohali": "PB",
    "ludhiana": "PB",
    "amritsar": "PB",
    "bhopal": "MP",
    "indore": "MP",
    "jabalpur": "MP",
    "patna": "BR",
    "gaya": "BR",
    "guwahati": "AS",
    "bhubaneswar": "OD",
    "cuttack": "OD",
    "ranchi": "JH",
    "jamshedpur": "JH",
    "raipur": "CG",
    "dehradun": "UK",
    "goa": "GA",
    "panaji": "GA",
}

# 定向 IP 查询源：城市名 → 邦码。顺序与 stripe_checkout 一致。
_BILLING_GEO_SOURCES = (
    ("ipinfo", "https://ipinfo.io/json"),
    ("ipapi", "https://ipapi.co/json/"),
    ("ipwho", "https://ipwho.is/"),
)


def _billing_geo_country_city(payload: dict[str, Any], source: str) -> tuple[str, str]:
    if not isinstance(payload, dict):
        return "", ""
    if source == "ipinfo":
        return str(payload.get("country") or "").upper(), str(payload.get("city") or "")
    if source == "ipapi":
        return (
            str(payload.get("country_code") or payload.get("country") or "").upper(),
            str(payload.get("city") or ""),
        )
    if source == "ipwho":
        if payload.get("success") is False:
            return "", ""
        return str(payload.get("country_code") or "").upper(), str(payload.get("city") or "")
    return "", ""


def detect_exit_state(session: Any, *, timeout: int = 10) -> str:
    """Best-effort: resolve the proxy exit city to an Indian state code."""
    for source, url in _BILLING_GEO_SOURCES:
        try:
            response = session.get(
                url,
                headers={"Accept": "application/json"},
                timeout=timeout,
            )
        except Exception as exc:  # network probe must never break the chain
            log(f"账单地域探测失败（{source}）：{str(exc)[:120]}", "[WARN] ")
            continue
        if int(getattr(response, "status_code", 599) or 599) >= 400:
            continue
        try:
            payload = response.json() or {}
        except Exception:
            continue
        country, city = _billing_geo_country_city(payload, source)
        if country and country != "IN":
            log(f"账单地域探测（{source}）：出口国家 {country}，非印度，保留默认账单", "[WARN] ")
            return ""
        state = IN_CITY_STATE.get(re.sub(r"\s+", " ", city.strip().lower()))
        if state:
            log(f"账单地域探测（{source}）：出口城市 {city} → 邦 {state}")
            return state
        if city:
            log(f"账单地域探测（{source}）：出口城市 {city} 无匹配邦码，保留默认账单")
        return ""
    return ""


def _billing_identity_for_state(seed: int, step: int, state_filter: str) -> tuple[dict[str, str], str] | None:
    """Like ``_billing_identity`` but only accepts rows in ``state_filter``."""
    wanted = str(state_filter or "").strip().upper()
    if not wanted:
        return None
    rows = [row for row in IN_BILLING_ADDRESSES if str(row[3]).upper() == wanted]
    if not rows:
        return None
    mixed = (int(seed) + step * 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
    rng = random.Random(mixed)
    first_name, last_name = rng.choice(IN_BILLING_NAMES)
    street, city, postal_code, state = rng.choice(rows)
    house = f"{rng.randint(1, _BILLING_POOL_HOUSE_LIMIT)}{rng.choice(_BILLING_HOUSE_SUFFIXES)}"
    if billing_script() == "hindi":
        first_hi, last_hi = IN_BILLING_NAMES_HI.get((first_name, last_name), (first_name, last_name))
        name = f"{first_hi} {last_hi}"
        street_text = IN_BILLING_STREETS_HI.get((street, city)) or re.sub(
            r"^\d{1,4}[A-Za-z]?\s+", "", street
        ).strip() or street
        city_text = IN_BILLING_CITIES_HI.get(city, city)
    else:
        name = f"{first_name} {last_name}"
        street_text = re.sub(r"^\d{1,4}[A-Za-z]?\s+", "", street).strip() or street
        city_text = city
    line1 = f"{house} {street_text}"
    profile = {
        "email": build_email(first_name, last_name, rng=rng),
        "name": name,
        "country": "IN",
        "line1": line1,
        "line2": "",
        "city": city_text,
        "postal_code": postal_code,
        "state": state,
    }
    identity = "|".join((name, line1, city_text, postal_code, state)).lower()
    return profile, identity


def align_billing_to_exit(
    profile: dict[str, str],
    account_id: str,
    state_code: str,
) -> dict[str, str]:
    """Move a billing identity into ``state_code`` while keeping it sticky."""
    wanted = str(state_code or "").strip().upper()
    if not wanted or str(profile.get("state") or "").upper() == wanted:
        return profile
    account_key = _billing_account_key(account_id)
    if not account_key:
        seeded = _billing_identity_for_state(secrets.randbits(63), 0, wanted)
        return dict(seeded[0]) if seeded else profile
    with BillingPoolLock():
        data = _load_billing_pool()
        script = billing_script()
        slot = f"{account_key}:{script}:{wanted}"
        entry = data["accounts"].get(slot)
        if isinstance(entry, dict) and isinstance(entry.get("profile"), dict):
            cached = {str(k): str(v) for k, v in entry["profile"].items()}
            if cached.get("line1") and cached.get("postal_code"):
                return cached
        used = {str(key) for key in data["identities"]}
        seed = _billing_seed(account_id)
        candidate: dict[str, str] | None = None
        identity = ""
        for step in range(_BILLING_POOL_MAX_PROBE):
            seeded = _billing_identity_for_state(seed, step, wanted)
            if seeded is None:
                break
            candidate, identity = seeded
            if identity not in used:
                break
        if candidate is None:
            return profile
        data["identities"][identity] = account_key
        data["accounts"][slot] = {
            "identity": identity,
            "profile": candidate,
            "script": script,
            "state": wanted,
            "assigned_at": time.time(),
        }
        try:
            _save_billing_pool(data)
        except OSError:
            pass
        return dict(candidate)


def _billing_identity(seed: int, step: int) -> tuple[dict[str, str], str]:
    """Build one deterministic candidate identity from (seed, step)."""
    mixed = (int(seed) + step * 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
    rng = random.Random(mixed)
    first_name, last_name = rng.choice(IN_BILLING_NAMES)
    street, city, postal_code, state = rng.choice(IN_BILLING_ADDRESSES)
    house = f"{rng.randint(1, _BILLING_POOL_HOUSE_LIMIT)}{rng.choice(_BILLING_HOUSE_SUFFIXES)}"
    if billing_script() == "hindi":
        first_hi, last_hi = IN_BILLING_NAMES_HI.get((first_name, last_name), (first_name, last_name))
        name = f"{first_hi} {last_hi}"
        street_text = IN_BILLING_STREETS_HI.get((street, city)) or re.sub(
            r"^\d{1,4}[A-Za-z]?\s+", "", street
        ).strip() or street
        city_text = IN_BILLING_CITIES_HI.get(city, city)
    else:
        name = f"{first_name} {last_name}"
        # Curated streets already carry a house number for readability; strip it
        # so the generated house number does not stack ("157 55 Jubilee Hills Road").
        street_text = re.sub(r"^\d{1,4}[A-Za-z]?\s+", "", street).strip() or street
        city_text = city
    line1 = f"{house} {street_text}"
    profile = {
        "email": build_email(first_name, last_name, rng=rng),
        "name": name,
        "country": "IN",
        "line1": line1,
        "line2": "",
        "city": city_text,
        "postal_code": postal_code,
        "state": state,
    }
    identity = "|".join((name, line1, city_text, postal_code, state)).lower()
    return profile, identity


def _load_billing_pool() -> dict[str, Any]:
    path = billing_pool_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except (FileNotFoundError, ValueError, OSError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    accounts = data.get("accounts")
    identities = data.get("identities")
    return {
        "version": BILLING_POOL_VERSION,
        "accounts": accounts if isinstance(accounts, dict) else {},
        "identities": identities if isinstance(identities, dict) else {},
    }


def _save_billing_pool(data: dict[str, Any]) -> None:
    path = billing_pool_path()
    data["version"] = BILLING_POOL_VERSION
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    os.replace(temporary, path)


class BillingPoolLock:
    """Cross-process lock so concurrent tasks never take the same address."""

    def __init__(self, timeout: float = 30.0, stale_after: float = 90.0) -> None:
        self._timeout = timeout
        self._stale_after = stale_after
        self._fd: int | None = None
        path = billing_pool_path()
        self._path = path.with_name(path.name + ".lock")

    def __enter__(self) -> "BillingPoolLock":
        _BILLING_POOL_LOCK.acquire()
        deadline = time.time() + self._timeout
        while True:
            try:
                self._fd = os.open(str(self._path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                try:
                    if time.time() - self._path.stat().st_mtime > self._stale_after:
                        self._path.unlink()
                        continue
                except OSError:
                    pass
                if time.time() > deadline:
                    return self
                time.sleep(0.05)
            except OSError:
                return self

    def __exit__(self, *_exc: Any) -> bool:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
            try:
                self._path.unlink()
            except OSError:
                pass
        _BILLING_POOL_LOCK.release()
        return False


def _assigned_billing_profile(account_key: str, account_id: str) -> dict[str, str]:
    """Return this account's sticky identity, allocating a unique one if new."""
    with BillingPoolLock():
        data = _load_billing_pool()
        script = billing_script()
        # One sticky assignment per (account, script) so switching the billing
        # language never destroys the previously assigned identity.
        slot = f"{account_key}:{script}"
        entry = data["accounts"].get(slot)
        if isinstance(entry, dict) and isinstance(entry.get("profile"), dict):
            profile = {str(key): str(value) for key, value in entry["profile"].items()}
            if profile.get("line1") and profile.get("postal_code"):
                return profile
        used = {str(key) for key in data["identities"]}
        seed = _billing_seed(account_id)
        candidate: dict[str, str] | None = None
        identity = ""
        for step in range(_BILLING_POOL_MAX_PROBE):
            candidate, identity = _billing_identity(seed, step)
            if identity not in used:
                break
        if candidate is None:
            candidate, identity = _billing_identity(secrets.randbits(63), 0)
        data["identities"][identity] = account_key
        data["accounts"][slot] = {
            "identity": identity,
            "profile": candidate,
            "script": script,
            "assigned_at": time.time(),
        }
        try:
            _save_billing_pool(data)
        except OSError:
            pass
        return dict(candidate)


def upi_billing_profile(account_id: str = "") -> dict[str, str]:
    """Return a sticky, collision-free Indian billing identity for one account.

    Every distinct account keeps its own (name, house + street, city, PIN,
    state) tuple: the assignment is persisted in ``billing_assignments.json``
    so retries reuse the same billing details and two accounts never share the
    same address.
    """
    account_key = _billing_account_key(account_id)
    if account_key:
        profile = _assigned_billing_profile(account_key, account_id)
    else:
        profile, _identity = _billing_identity(secrets.randbits(63), 0)

    if env_bool("UPI_USE_FIXED_BILLING", False):
        profile = dict(DEFAULT_UPI_BILLING)
    env_map = {
        "email": "UPI_EMAIL",
        "name": "UPI_NAME",
        "country": "UPI_BILLING_COUNTRY",
        "line1": "UPI_LINE1",
        "line2": "UPI_LINE2",
        "city": "UPI_CITY",
        "postal_code": "UPI_POSTAL_CODE",
        "state": "UPI_STATE",
    }
    for key, env_name in env_map.items():
        value = os.environ.get(env_name, "").strip()
        if value:
            profile[key] = value
    profile["country"] = normalize_country(profile.get("country", "IN"))
    return profile


def upi_billing_profile_for_exit(
    account_id: str = "",
    *,
    session: Any = None,
) -> dict[str, str]:
    """账单资料：默认粘性身份；开关开启时按代理出口邦州对齐。"""
    profile = upi_billing_profile(account_id)
    if session is None or not billing_align_exit_enabled():
        return profile
    state_code = detect_exit_state(session)
    if not state_code:
        return profile
    aligned = align_billing_to_exit(profile, account_id, state_code)
    if aligned.get("state") != profile.get("state"):
        log(
            f"账单地址已对齐代理出口区域：{profile.get('city') or '-'}({profile.get('state') or '-'})"
            f" → {aligned.get('city') or '-'}({aligned.get('state') or '-'})"
        )
    return aligned


def stripe_update_customer_data(
    stripe: requests.Session,
    cs_id: str,
    stripe_pk: str,
    ctx: dict[str, Any],
    billing: dict[str, str],
) -> bool:
    body: dict[str, Any] = {
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
        "expected_amount": str(ctx.get("checkout_amount") or 0),
        "elements_session_client[session_id]": ctx["elements_session_id"],
        "elements_session_client[stripe_js_id]": ctx["stripe_js_id"],
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[locale]": ctx["locale"],
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "customer_data[email]": billing["email"],
        "customer_data[name]": billing["name"],
        "customer_data[address][country]": billing["country"],
        "customer_data[address][line1]": billing["line1"],
        "customer_data[address][city]": billing["city"],
        "customer_data[address][postal_code]": billing["postal_code"],
    }
    if billing.get("line2"):
        body["customer_data[address][line2]"] = billing["line2"]
    if billing.get("state"):
        body["customer_data[address][state]"] = billing["state"]

    url = f"https://api.stripe.com/v1/payment_pages/{cs_id}"
    try:
        resp = stripe.post(url, data=body, timeout=DEFAULT_TIMEOUT)
        dump_http(resp, "customer_data_update_br", body, "POST", url, force=resp.status_code >= 400)
        if resp.status_code < 400:
            log(
                f"印度 customer_data 已提交: {billing['name']} / {billing['city']} / {billing['postal_code']}"
            )
            return True
        if is_checkout_not_active_error(resp.text):
            raise RuntimeError("checkout_not_active_session")
        log(f"印度 customer_data 提交失败 HTTP {resp.status_code}: {resp.text[:180]}", "[WARN] ")
    except Exception as exc:
        if is_checkout_not_active_error(exc):
            raise
        log(f"印度 customer_data 提交异常: {exc}", "[WARN] ")
    return False


def stripe_update_tax_region(
    stripe: requests.Session,
    cs_id: str,
    stripe_pk: str,
    ctx: dict[str, Any],
    billing: dict[str, str],
) -> bool:
    body: dict[str, Any] = {
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
        "elements_session_client[session_id]": ctx["elements_session_id"],
        "elements_session_client[stripe_js_id]": ctx["stripe_js_id"],
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_session_client[locale]": ctx["locale"],
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_options_client[saved_payment_method][enable_save]": saved_payment_value(),
        "elements_options_client[saved_payment_method][enable_redisplay]": saved_payment_value(),
        "client_attribution_metadata[merchant_integration_additional_elements][0]": "expressCheckout",
        "client_attribution_metadata[merchant_integration_additional_elements][1]": "payment",
        "client_attribution_metadata[merchant_integration_additional_elements][2]": "address",
        "tax_region[country]": billing["country"],
        "tax_region[postal_code]": billing["postal_code"],
        "tax_region[line1]": billing["line1"],
        "tax_region[city]": billing["city"],
    }
    if billing.get("state"):
        body["tax_region[state]"] = billing["state"]

    url = f"https://api.stripe.com/v1/payment_pages/{cs_id}"
    try:
        resp = stripe.post(url, data=body, timeout=DEFAULT_TIMEOUT)
        dump_http(resp, "tax_region_update", body, "POST", url, force=resp.status_code >= 400)
        if resp.status_code < 400:
            log(f"tax_region 已提交: {billing['country']} / {billing['city']} {billing['postal_code']}")
            return True
        if is_checkout_not_active_error(resp.text):
            raise RuntimeError("checkout_not_active_session")
        log(f"tax_region 提交失败 HTTP {resp.status_code}: {resp.text[:180]}", "[WARN] ")
    except Exception as exc:
        if is_checkout_not_active_error(exc):
            raise
        log(f"tax_region 提交异常: {exc}", "[WARN] ")
    return False


def checkout_snapshot(chatgpt: requests.Session, checkout: dict[str, str], billing: dict[str, str]) -> None:
    cs_id = checkout["cs_id"]
    processor = processor_entity_for_country(checkout.get("billing_country", "IN"), checkout.get("processor_entity") or "")
    checkout_page_url = f"https://chatgpt.com/checkout/{processor}/{cs_id}"
    body = {
        "snapshot": {
            "billing_address": {
                "name": billing["name"],
                "address": {
                    "line1": billing["line1"],
                    "city": billing["city"],
                    "country": billing["country"],
                    "postal_code": billing["postal_code"],
                    "state": billing.get("state", ""),
                },
            }
        }
    }
    try:
        resp = chatgpt.post(
            "https://chatgpt.com/backend-api/payments/checkout/snapshot",
            json=body,
            headers={
                "Referer": checkout_page_url,
                "x-openai-target-path": "/backend-api/payments/checkout/snapshot",
                "x-openai-target-route": "/backend-api/payments/checkout/snapshot",
            },
            timeout=CHATGPT_TIMEOUT,
        )
        dump_http(resp, "checkout_snapshot", body, "POST", "https://chatgpt.com/backend-api/payments/checkout/snapshot", force=env_bool("UPI_DUMP_WARMUP", False) or resp.status_code >= 400)
        if resp.status_code >= 400:
            if is_checkout_not_active_error(resp.text):
                raise RuntimeError("checkout_not_active_session")
            log(f"checkout snapshot 失败 HTTP {resp.status_code}: {resp.text[:180]}", "[WARN] ")
        else:
            log("checkout snapshot 已提交")
    except Exception as exc:
        if is_checkout_not_active_error(exc):
            raise
        log(f"checkout snapshot 异常: {exc}", "[WARN] ")


def stripe_create_upi_pm(stripe: requests.Session, cs_id: str, stripe_pk: str, billing: dict[str, str], ctx: dict[str, Any]) -> str:
    body: dict[str, Any] = {
        "billing_details[name]": billing.get("name") or "Aisha Sharma",
        "billing_details[email]": billing.get("email") or "redacted@example.invalid",
        "billing_details[address][country]": billing.get("country") or "IN",
        "billing_details[address][line1]": billing.get("line1") or "24 Park Street",
        "billing_details[address][city]": billing.get("city") or "Kolkata",
        "billing_details[address][postal_code]": billing.get("postal_code") or "700016",
        "type": "upi",
        "client_attribution_metadata[checkout_session_id]": cs_id,
        "key": stripe_pk,
    }
    if billing.get("state"):
        body["billing_details[address][state]"] = billing["state"]

    resp = stripe.post("https://api.stripe.com/v1/payment_methods", data=body, timeout=DEFAULT_TIMEOUT)
    dump_http(resp, "upi_pm", body, "POST", "https://api.stripe.com/v1/payment_methods", force=resp.status_code >= 400)
    if resp.status_code >= 400:
        raise RuntimeError(f"创建 UPI PM 失败 HTTP {resp.status_code}: {resp.text[:500]}")
    pm_id = str((resp.json() or {}).get("id") or "")
    if not pm_id.startswith("pm_"):
        raise RuntimeError(f"创建 UPI PM 响应异常: {resp.text[:300]}")
    return pm_id


def add_inline_upi_payment_method_data(body: dict[str, Any], cs_id: str, billing: dict[str, str], ctx: dict[str, Any]) -> None:
    body.update(
        {
            "payment_method_data[type]": "upi",
            "payment_method_data[allow_redisplay]": "limited",
            "payment_method_data[billing_details][name]": billing["name"],
            "payment_method_data[billing_details][email]": billing["email"],
            "payment_method_data[billing_details][address][country]": billing["country"],
            "payment_method_data[billing_details][address][line1]": billing["line1"],
            "payment_method_data[billing_details][address][city]": billing["city"],
            "payment_method_data[billing_details][address][postal_code]": billing["postal_code"],
            "payment_method_data[payment_user_agent]": f"stripe.js/{random_runtime_version()}; stripe-js-v3/{random_runtime_version()}; payment-element; deferred-intent",
            "payment_method_data[referrer]": "https://chatgpt.com",
            "payment_method_data[time_on_page]": str(random.randint(18000, 55000)),
            "payment_method_data[client_attribution_metadata][checkout_session_id]": cs_id,
            "payment_method_data[client_attribution_metadata][client_session_id]": ctx["stripe_js_id"],
            "payment_method_data[client_attribution_metadata][checkout_config_id]": ctx.get("config_id") or "",
            "payment_method_data[client_attribution_metadata][elements_session_id]": ctx["elements_session_id"],
            "payment_method_data[client_attribution_metadata][elements_session_config_id]": ctx["elements_session_config_id"],
            "payment_method_data[client_attribution_metadata][merchant_integration_source]": "elements",
            "payment_method_data[client_attribution_metadata][merchant_integration_subtype]": "payment-element",
            "payment_method_data[client_attribution_metadata][merchant_integration_version]": "2021",
            "payment_method_data[client_attribution_metadata][payment_intent_creation_flow]": "deferred",
            "payment_method_data[client_attribution_metadata][payment_method_selection_flow]": "automatic",
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][0]": "expressCheckout",
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][1]": "payment",
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][2]": "address",
        }
    )
    if billing.get("state"):
        body["payment_method_data[billing_details][address][state]"] = billing["state"]


def processor_entity_for_country(country: str, processor_entity: str = "") -> str:
    if processor_entity:
        return processor_entity
    return "openai_llc" if normalize_country(country) == "US" else "openai_ie"


def stripe_checkout_long_url(cs_id: str, country: str, processor_entity: str) -> str:
    processor = processor_entity_for_country(country, processor_entity)
    success = f"https://chatgpt.com/checkout/verify?stripe_session_id={cs_id}&processor_entity={processor}&plan_type=plus"
    return (
        f"https://checkout.stripe.com/c/pay/{cs_id}"
        f"?returned_from_redirect=true&ui_mode=custom&return_url={quote(success, safe='')}"
    )


def to_openai_pay_url(stripe_hosted_url: str) -> str:
    url = str(stripe_hosted_url or "").strip()
    if not url:
        return ""
    if url.startswith("https://checkout.stripe.com"):
        return "https://pay.openai.com" + url[len("https://checkout.stripe.com") :]
    parsed = urlsplit(url)
    if parsed.netloc.lower() == "checkout.stripe.com":
        return urlunsplit((parsed.scheme or "https", "pay.openai.com", parsed.path, parsed.query, parsed.fragment))
    return url


def stripe_confirm_return_url(cs_id: str, checkout: dict[str, str], stripe_hosted_url: str) -> str:
    country = normalize_country(checkout.get("billing_country") or "IN")
    processor = processor_entity_for_country(country, checkout.get("processor_entity") or "")
    success = f"https://chatgpt.com/checkout/verify?stripe_session_id={cs_id}&processor_entity={processor}&plan_type=plus"
    hosted = to_openai_pay_url(stripe_hosted_url) or stripe_checkout_long_url(cs_id, country, processor)
    if "pay.openai.com/" in hosted or "checkout.stripe.com/" in hosted:
        parsed = urlsplit(hosted)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query.setdefault("success_return_url", success)
        # 对齐成功实现：显式声明走 UPI 重定向 + custom checkout，
        # 避免 Stripe 把这次确认当成普通卡片流程处理。
        query.setdefault("redirect_pm_type", "upi")
        query.setdefault("ui_mode", "custom")
        query.setdefault("lid", str(uuid.uuid4()))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))
    return hosted


def stripe_confirm_upi(
    stripe: requests.Session,
    cs_id: str,
    pm_id: str,
    stripe_pk: str,
    init_payload: dict[str, Any],
    ctx: dict[str, Any],
    checkout: dict[str, str],
    stripe_hosted_url: str,
    billing: dict[str, str],
) -> dict[str, Any]:
    runtime_version = str(ctx.get("runtime_version") or DEFAULT_STRIPE_RUNTIME_VERSION)
    expected_amount = ctx.get("checkout_amount")
    if expected_amount is None:
        expected_amount, _amount_source = amount_from_payload(init_payload)
    body = {
        "eid": "NA",
        "expected_amount": os.environ.get("PP_EXPECTED_AMOUNT", "").strip() or str(expected_amount),
        "expected_payment_method_type": "upi",
        "return_url": stripe_confirm_return_url(cs_id, checkout, stripe_hosted_url),
        "_stripe_version": str(ctx.get("stripe_version") or STRIPE_VERSION_FULL),
        "guid": str(ctx.get("guid") or stripe_browser_id()),
        "muid": str(ctx.get("muid") or stripe_browser_id()),
        "sid": str(ctx.get("sid") or stripe_browser_id()),
        "key": stripe_pk,
        "version": runtime_version,
        "init_checksum": str(init_payload.get("init_checksum") or ctx.get("init_checksum") or ""),
        "client_attribution_metadata[client_session_id]": str(ctx.get("client_session_id") or ctx["stripe_js_id"]),
        "client_attribution_metadata[checkout_session_id]": cs_id,
        "client_attribution_metadata[checkout_config_id]": ctx.get("config_id") or "",
        "client_attribution_metadata[merchant_integration_source]": "checkout",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[merchant_integration_version]": "custom_checkout",
        "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
        # 我们显式传了 payment_method，声明 automatic 与实际不符；
        # 成功实现（upi-zero-link）用的是 merchant_specified。
        "client_attribution_metadata[payment_method_selection_flow]": "merchant_specified",
        "tax_id_collection[purchasing_as_business]": "false",
        "client_attribution_metadata[elements_session_id]": ctx["elements_session_id"],
        "client_attribution_metadata[elements_session_config_id]": ctx["elements_session_config_id"],
        "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
        "client_attribution_metadata[merchant_integration_additional_elements][1]": "address",
        "consent[terms_of_service]": "accepted",
        "link_brand": "link",
    }
    body.update(stripe_elements_session_params(ctx))
    if env_bool("UPI_CONFIRM_INLINE_PM", False):
        add_inline_upi_payment_method_data(body, cs_id, billing, ctx)
    else:
        body["payment_method"] = pm_id
    url = f"https://api.stripe.com/v1/payment_pages/{cs_id}/confirm"
    resp = stripe.post(url, data=body, timeout=DEFAULT_TIMEOUT)
    dump_http(resp, "upi_confirm", body, "POST", url, force=True)
    if resp.status_code >= 400:
        raise RuntimeError(f"UPI confirm 失败 HTTP {resp.status_code}: {resp.text[:500]}")
    return resp.json() or {}


def collect_urls(payload: Any, urls: list[str] | None = None) -> list[str]:
    found = urls if urls is not None else []
    if isinstance(payload, str):
        for match in re.findall(r"https?://[^\s\"'<>]+", payload):
            found.append(match.rstrip("),.;]"))
        for match in re.findall(r"data:image/(?:png|svg\+xml|jpeg);base64,[A-Za-z0-9+/=]+", payload):
            found.append(match)
    elif isinstance(payload, dict):
        for value in payload.values():
            collect_urls(value, found)
    elif isinstance(payload, list):
        for item in payload:
            collect_urls(item, found)
    return found


def is_resource_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    if is_known_static_host(url):
        return True
    return path.endswith(
        (
            ".js",
            ".css",
            ".map",
            ".woff",
            ".woff2",
            ".ttf",
            ".otf",
            ".ico",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".webp",
        )
    )


def is_known_static_host(url: str) -> bool:
    host = (urlparse(url).netloc or "").lower()
    return host in {
        "stripe-camo.global.ssl.fastly.net",
        "files.stripe.com",
        "js.stripe.com",
        "m.stripe.network",
        "q.stripe.com",
    }


def is_upi_instructions_url(url: str) -> bool:
    parsed = urlparse(str(url or "").strip())
    return (
        parsed.scheme in {"http", "https"}
        and (parsed.netloc or "").lower() == "payments.stripe.com"
        and (parsed.path or "").lower().startswith("/upi/instructions/")
    )


def is_upi_qr_asset_url(url: str) -> bool:
    parsed = urlparse(str(url or "").strip())
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    return (
        parsed.scheme in {"http", "https"}
        and host == "qr.stripe.com"
        and (path.endswith(".png") or path.endswith(".svg") or "/live_" in path)
    )


def preferred_upi_result_url(redirect_url: str, qr_urls: list[str] | None = None) -> str:
    """Prefer the hosted UPI instructions page, then a live Stripe QR asset."""
    redirect = str(redirect_url or "").strip()
    if is_upi_instructions_url(redirect):
        return redirect
    candidates = list(dict.fromkeys(str(item or "").strip() for item in (qr_urls or [])))
    for candidate in candidates:
        if is_upi_instructions_url(candidate):
            return candidate
    for candidate in candidates:
        if is_upi_qr_asset_url(candidate) and candidate.lower().endswith(".png"):
            return candidate
    for candidate in candidates:
        if is_upi_qr_asset_url(candidate):
            return candidate
    return redirect


def delivery_result_url(redirect_url: str, qr_urls: list[str] | None = None) -> str:
    """Deliverable UPI link: the real instructions page always wins.

    只有 ``payments.stripe.com/upi/instructions/...`` 能直接扫码付款；托管结账页
    （``pay.openai.com`` / ``checkout.stripe.com``）只是 0 元链的人工兜底，必须在
    结果里被明确区分，不能盖住真正的 instructions 链接。
    """
    instructions = next(
        (
            item
            for item in [
                str(redirect_url or "").strip(),
                *[str(value or "").strip() for value in (qr_urls or [])],
            ]
            if is_upi_instructions_url(item)
        ),
        "",
    )
    return instructions or str(redirect_url or "").strip()


def upi_capture_metadata(candidates: list[str]) -> dict[str, Any]:
    unique = list(dict.fromkeys(str(item or "").strip() for item in candidates if str(item or "").strip()))
    qr_urls = [
        item
        for item in unique
        if is_upi_qr_asset_url(item) or (is_qr_candidate(item) and not is_known_static_host(item))
    ]
    qr_urls = list(dict.fromkeys(qr_urls))
    return {
        "qr_urls": qr_urls,
        "upi_qr_png": next(
            (item for item in qr_urls if is_upi_qr_asset_url(item) and item.lower().endswith(".png")),
            "",
        ),
        "upi_qr_svg": next(
            (item for item in qr_urls if is_upi_qr_asset_url(item) and item.lower().endswith(".svg")),
            "",
        ),
        "upi_instructions_url": next((item for item in unique if is_upi_instructions_url(item)), ""),
    }


def extract_upi_deep_link_from_html(html: str) -> dict[str, Any]:
    """Parse a Stripe UPI instructions page for the raw ``upi://`` deep link.

    The hosted instructions page embeds a base64 JSON blob in
    ``<meta id="payload" data-message="...">``; it carries ``mobile_auth_url``
    (the scannable UPI URI) and the QR expiry. Falls back to the
    ``qr.stripe.com`` image URLs when only those are present.
    """
    text = str(html or "")
    result: dict[str, Any] = {}
    if not text:
        return result
    meta_match = re.search(
        r"<meta\b[^>]*\bid=[\"']payload[\"'][^>]*\bdata-message=[\"']([^\"']+)[\"']",
        text,
        re.IGNORECASE,
    )
    if not meta_match:
        meta_match = re.search(
            r"<meta\b[^>]*\bdata-message=[\"']([^\"']+)[\"'][^>]*\bid=[\"']payload[\"']",
            text,
            re.IGNORECASE,
        )
    if meta_match:
        raw = meta_match.group(1).replace("&quot;", '"').strip()
        raw = raw.replace("-", "+").replace("_", "/")
        padded = raw + "=" * (-len(raw) % 4)
        try:
            payload = json.loads(base64.b64decode(padded).decode("utf-8", "replace"))
        except Exception:
            payload = None
        if isinstance(payload, dict):
            for key in ("upi_uri", "mobile_auth_url"):
                value = str(payload.get(key) or "").strip()
                if value.startswith("upi://"):
                    result["upi_uri"] = value
                    break
            for key in ("expires_at", "expires_after_timestamp", "qr_expires_at"):
                try:
                    expires = int(payload.get(key) or 0)
                except (TypeError, ValueError):
                    expires = 0
                if expires > 0:
                    result["expires_at"] = expires
                    break
            # SetupIntent 生命周期状态：UPI instructions 链是「一次性支付动作」，
            # Stripe 会在用户未于窗口内完成授权时把委托判 abandoned → canceled，
            # 此时链接仍返回 HTTP 200（页面还在），但**已无法完成支付**。
            # 实测：16:00 出链、16:40 回访，status=canceled / reason=abandoned。
            # 因此必须把状态和有效期一起交付，让用户知道「还剩多久必须用掉」。
            intent_state = str(payload.get("intent_state") or "").strip().lower()
            if intent_state:
                result["intent_state"] = intent_state
            client_secret = str(payload.get("client_secret") or "").strip()
            if client_secret.startswith("seti_"):
                result["setup_intent_id"] = client_secret.split("_secret_")[0]
    for img_match in re.finditer(r"<img\b[^>]*\bsrc=[\"']([^\"']+)[\"']", text, re.IGNORECASE):
        src = img_match.group(1).replace("&amp;", "&").strip()
        if "qr.stripe.com" not in src:
            continue
        if src.lower().endswith(".svg") and not result.get("qr_image_svg"):
            result["qr_image_svg"] = src
        elif src.lower().endswith(".png") and not result.get("qr_image_png"):
            result["qr_image_png"] = src
    return result


# UPI instructions 链已作废的 SetupIntent 状态：链接仍能打开但无法完成支付。
UPI_INVALID_INTENT_STATES = {"canceled", "cancelled", "succeeded", "requires_payment_method"}


def _upi_instructions_url(value: str) -> str:
    """从一批 URL 里取出第一条 payments.stripe.com/upi/instructions 链。"""
    for item in (value,) if isinstance(value, str) else (value or []):
        text = str(item or "").strip()
        if is_upi_instructions_url(text):
            return text
    return ""


def upi_delivery_dead_reason(redirect_url: str, qr_urls: list[str] | None = None) -> str:
    """交付前校验 UPI instructions 链是否已失效；返回原因，空串表示可交付。

    UPI instructions 链是一次性支付动作：Stripe 会在用户未于窗口内
    完成授权时把 SetupIntent 判为 abandoned → canceled。此时链接仍返回
    HTTP 200（页面还在），但已无法完成支付。实测：16:00 出链、16:40
    回访，status=canceled / cancellation_reason=abandoned。

    这里只做一次轻量 GET（跟 hydrate 同一个页面，不额外请求上游），
    解析 payload 里的 intent_state 与 expires_at。任何网络异常一律放行，
    避免把可用的链误判成死链。
    """
    if not env_bool("UPI_DELIVERY_VALIDATE", True):
        return ""
    url = _upi_instructions_url(redirect_url)
    if not url:
        # 没有 instructions 链（例如只交付托管链），不适用该校验
        return ""
    try:
        resp = requests.get(
            url,
            timeout=min(20, DEFAULT_TIMEOUT),
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "https://js.stripe.com/",
                "User-Agent": DEFAULT_USER_AGENT,
            },
        )
    except Exception as exc:  # noqa: BLE001 - 校验失败不能阻断交付
        log(f"UPI 链交付前校验请求异常（已放行）: {str(exc)[:120]}", "[WARN] ")
        return ""
    status_code = int(getattr(resp, "status_code", 0) or 0)
    if status_code >= 400:
        return f"链接返回 HTTP {status_code}，Stripe 已不再提供该支付入口"
    parsed = extract_upi_deep_link_from_html(getattr(resp, "text", "") or "")
    intent_state = str(parsed.get("intent_state") or "").strip().lower()
    if intent_state in UPI_INVALID_INTENT_STATES:
        return (
            f"Stripe SetupIntent 已于交付前失效"
            f"（intent_state={intent_state}），链接打得开但不能付款"
        )
    expires_at = int(parsed.get("expires_at") or 0)
    if expires_at and expires_at - time.time() <= 0:
        return (
            "该支付入口已过有效期（"
            f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(expires_at))}），"
            "Stripe 已回收授权委托"
        )
    return ""


def log_upi_delivery_validity(redirect_url: str, qr_urls: list[str] | None = None) -> None:
    """在成功交付后输出一行可读的有效期提示，供前端与运营判断剩余时间。"""
    url = _upi_instructions_url(redirect_url)
    if not url:
        return
    try:
        resp = requests.get(
            url,
            timeout=min(20, DEFAULT_TIMEOUT),
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "https://js.stripe.com/",
                "User-Agent": DEFAULT_USER_AGENT,
            },
        )
        parsed = extract_upi_deep_link_from_html(getattr(resp, "text", "") or "")
    except Exception:  # noqa: BLE001
        return
    expires_at = int(parsed.get("expires_at") or 0)
    intent_state = str(parsed.get("intent_state") or "").strip().lower()
    if not expires_at and not intent_state:
        return
    parts = []
    if intent_state:
        parts.append(f"intent_state={intent_state}")
    if expires_at:
        remaining = expires_at - time.time()
        if remaining > 0:
            parts.append(
                "请在 %.0f 分钟内完成 UPI 授权，否则委托会被 Stripe 回收"
                % (remaining / 60)
            )
            parts.append(
                "到期时间 %s"
                % time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(expires_at))
            )
        else:
            parts.append("已过有效期")
    log("UPI 支付入口有效性：" + "；".join(parts))



def hydrate_upi_deep_link(session: Any, candidates: list[str]) -> dict[str, Any]:
    """Fetch the hosted instructions page and pull the real ``upi://`` URI."""
    if not env_bool("UPI_HYDRATE_DEEP_LINK", True):
        return {}
    url = next(
        (str(item).strip() for item in (candidates or []) if is_upi_instructions_url(str(item or ""))),
        "",
    )
    if not url:
        return {}
    try:
        resp = session.get(
            url,
            timeout=DEFAULT_TIMEOUT,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "https://js.stripe.com/",
            },
        )
    except Exception as exc:  # noqa: BLE001 - hydration is best effort
        log(f"UPI instructions 页面获取失败: {str(exc)[:140]}", "[WARN] ")
        return {}
    try:
        status_code = int(getattr(resp, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status_code = 0
    if status_code >= 400:
        log(f"UPI instructions 页面 HTTP {status_code}，跳过 deep link 解析", "[WARN] ")
        return {}
    parsed = extract_upi_deep_link_from_html(getattr(resp, "text", "") or "")
    if parsed.get("upi_uri"):
        log(f"UPI 深链已解析: {str(parsed['upi_uri'])[:60]}…")
    # 交付前校验：UPI instructions 链是一次性支付动作，Stripe 会在用户未于窗口内
    # 完成授权时把委托判 abandoned → canceled。此时链接仍返回 HTTP 200
    # （页面还在），但**已无法完成支付**。实测：16:00 出链、16:40 回访，
    # status=canceled / reason=abandoned。这里把状态和剩余有效期一起带回给父进程与前端。
    intent_state = str(parsed.get("intent_state") or "").strip().lower()
    expires_at = int(parsed.get("expires_at") or 0)
    if expires_at:
        remaining = expires_at - time.time()
        parsed["seconds_remaining"] = int(remaining)
        if remaining <= 0:
            log(
                "UPI instructions 链已过有效期（"
                f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(expires_at))}），"
                "Stripe 已回收该授权委托，链接无法完成支付",
                "[WARN] ",
            )
    if intent_state in UPI_INVALID_INTENT_STATES:
        parsed["dead"] = True
        log(
            f"UPI instructions 链已作废（Stripe intent_state={intent_state}）："
            "链接仍可打开但不能完成付款，"
            "请重新提链获取新的支付入口",
            "[WARN] ",
        )
    return parsed



def _upi_page_frames(page: Any) -> list[Any]:
    try:
        frames = list(getattr(page, "frames", []) or [])
    except Exception:
        frames = []
    return frames or [page]


def _upi_locator_visible(locator: Any) -> bool:
    try:
        return bool(locator.first.is_visible())
    except Exception:
        return False


def _upi_hosted_captcha_kind(page: Any) -> str:
    """Return the captcha kind when the hosted checkout page is *actually* challenged.

    必须判「可见」的挑战元素，不能只看 HTML：Stripe 托管页会预加载 hCaptcha
    脚本，整页文本里出现 ``hcaptcha`` 并不代表弹出了验证码。只有真的出现可见
    挑战时才说明当前出口 IP / 指纹已被标记，此时应换出口重试而不是继续等。
    """
    selectors = (
        'iframe[src*="hcaptcha.com"][data-hcaptcha-widget-id]',
        'iframe[src*="newassets.hcaptcha.com"]',
        'iframe[title*="hCaptcha" i]',
        'iframe[src*="recaptcha/api2/anchor"]',
        '[data-hcaptcha-widget-id]',
        '#hcaptcha-box',
    )
    texts = (
        r"verify you are human",
        r"please verify you are a human",
        r"are you a robot",
    )
    for scope in _upi_page_frames(page)[:3]:
        for selector in selectors:
            try:
                locator = scope.locator(selector)
                if locator.count() > 0 and _upi_locator_visible(locator):
                    return "hcaptcha"
            except Exception:
                continue
        for pattern in texts:
            try:
                text_locator = scope.get_by_text(re.compile(pattern, re.IGNORECASE))
                if text_locator.count() > 0 and _upi_locator_visible(text_locator):
                    return "hcaptcha"
            except Exception:
                continue
    return ""


def _upi_hosted_risk_block_kind(page: Any, captcha_hits: int, page_error: str) -> str:
    """Detect Stripe's invisible-hCaptcha soft block on the hosted page.

    Stripe 用 hCaptcha 的不可见模式做风控：没有可见验证码，但页面会问后端
    ``getcaptcha``，失败时只回一句 ``Please try again.``，且提交按钮点了也不发
    confirm 请求。这种「软拦」必须和可见挑战一样处理——快速失败并换出口，
    否则只会白等满整个轮询窗口再报一个含义不清的 QR_NOT_FOUND。
    """
    if int(captcha_hits or 0) <= 0:
        return ""
    lowered = re.sub(r"\s+", " ", str(page_error or "")).strip().lower()
    if not lowered:
        return ""
    for marker in ("try again", "something went wrong", "unable to", "not able to"):
        if marker in lowered:
            return "hcaptcha-soft-block"
    return ""


def _upi_payment_method_selected(scope: Any) -> bool:
    selectors = (
        'input[type="radio"][value="upi" i]:checked',
        'input[type="radio"][id*="upi" i]:checked',
        'input[type="radio"][name*="upi" i]:checked',
        '[role="radio"][aria-checked="true"][aria-label*="upi" i]',
        '[role="radio"][aria-checked="true"]:has-text("UPI")',
        '[aria-selected="true"][data-testid*="upi" i]',
        '[data-state="checked"][data-testid*="upi" i]',
    )
    for selector in selectors:
        try:
            if scope.locator(selector).count() > 0:
                return True
        except Exception:
            continue
    return False


def _upi_checkout_page_diagnostic(page: Any) -> str:
    """Compact DOM/iframe diagnostic for a hosted checkout page without UPI.

    托管结账页拿不到 UPI 选项时，只有「页面没渲染支付方式」「验证码拦截」
    「只提供了 card」这几种可能，光看 ``payment method option missing``
    无法区分，所以把首屏关键信息一并带进错误里。
    """
    parts: list[str] = []
    try:
        title = re.sub(r"\s+", " ", str(page.title() or "")).strip()[:60]
        if title:
            parts.append(f"title={title}")
    except Exception:
        pass
    try:
        parts.append(f"url={(urlsplit(str(page.url or '')).netloc or '').lower()}")
    except Exception:
        pass
    frames = _upi_page_frames(page)
    parts.append(f"frames={len(frames)}")
    labels: list[str] = []
    for scope in frames[:3]:
        for selector in (
            '[data-testid^="payment-method-accordion-item-title"]',
            '[data-testid*="payment-method"]',
            '[role="radio"]',
            '[data-testid="hosted-payment-submit-button"]',
            'h1',
        ):
            try:
                locator = scope.locator(selector)
                count = min(locator.count(), 4)
            except Exception:
                continue
            for index in range(count):
                try:
                    text = re.sub(
                        r"\s+",
                        " ",
                        str(locator.nth(index).inner_text(timeout=1_500) or ""),
                    ).strip()
                except Exception:
                    continue
                if text and text not in labels:
                    labels.append(text[:32])
        if labels:
            break
    if labels:
        parts.append("options=" + "/".join(labels[:8]))
    try:
        html = str(page.content() or "")
    except Exception:
        html = ""
    lowered = html.lower()
    if lowered:
        kind = _upi_hosted_captcha_kind(page)
        if kind:
            parts.append(f"captcha={kind}")
        elif "hcaptcha" in lowered:
            # 只加载了脚本但没有可见挑战：不算被拦，仅记录便于对比。
            parts.append("captcha_script_loaded")
        if "upi" not in lowered:
            parts.append("html_without_upi_token")
    return "; ".join(parts) or "unavailable"


def _select_upi_payment_method(page: Any, timeout_ms: int) -> str:
    """Select UPI in the official Stripe Hosted Checkout page."""
    action_timeout = max(2_000, min(int(timeout_ms or 8_000), 8_000))
    deadline = time.monotonic() + max(3.0, min(action_timeout / 1000, 20.0))
    errors: list[str] = []

    def remember(label: str, exc: Any) -> None:
        detail = re.sub(r"\s+", " ", str(exc or "")).strip()[:140]
        if detail:
            errors.append(f"{label}:{detail}")
        if len(errors) > 12:
            del errors[:-12]

    while time.monotonic() < deadline:
        for frame_index, scope in enumerate(_upi_page_frames(page)):
            if _upi_payment_method_selected(scope):
                return f"already-selected:frame-{frame_index}"

            selectors = (
                ('input[type="radio"][value="upi" i]', True),
                ('input[type="radio"][id*="upi" i]', True),
                ('input[type="radio"][name*="upi" i]', True),
                ('[role="radio"][aria-label*="upi" i]', False),
                ('label[for*="upi" i]', False),
                ('[data-testid*="upi" i]', False),
                ('[data-value*="upi" i]', False),
            )
            for selector, use_check in selectors:
                try:
                    locator = scope.locator(selector)
                    count = min(locator.count(), 3)
                except Exception as exc:
                    remember(f"locate:{frame_index}:{selector}", exc)
                    continue
                for index in range(count):
                    item = locator.nth(index)
                    try:
                        item.scroll_into_view_if_needed(timeout=action_timeout)
                    except Exception:
                        pass
                    try:
                        if use_check:
                            item.check(force=True, timeout=action_timeout)
                        else:
                            item.click(force=True, timeout=action_timeout)
                        page.wait_for_timeout(350)
                        if _upi_payment_method_selected(scope):
                            return f"selector:frame-{frame_index}:{selector}"
                        # Some current Stripe layouts use a button-like option
                        # without exposing aria-checked immediately.
                        return f"selector-clicked:frame-{frame_index}:{selector}"
                    except Exception as exc:
                        remember(f"click:{frame_index}:{selector}", exc)

            try:
                labels = scope.get_by_text(re.compile(r"\bUPI\b", re.I), exact=False)
                label_count = min(labels.count(), 4)
            except Exception as exc:
                remember(f"text:{frame_index}", exc)
                labels = None
                label_count = 0
            for index in range(label_count):
                label = labels.nth(index)
                for ancestor in (
                    "xpath=ancestor::*[@role='radio'][1]",
                    "xpath=ancestor::label[1]",
                    "xpath=ancestor::button[1]",
                    "xpath=ancestor::*[@data-testid][1]",
                    "xpath=..",
                ):
                    try:
                        target = label.locator(ancestor)
                        if target.count() < 1:
                            continue
                        target.first.click(force=True, timeout=action_timeout)
                        page.wait_for_timeout(350)
                        return f"text:frame-{frame_index}:{ancestor}"
                    except Exception as exc:
                        remember(f"text-click:{frame_index}:{ancestor}", exc)
        page.wait_for_timeout(300)

    detail = " | ".join(errors[-6:]) or "payment method option missing"
    raise RuntimeError(
        f"{UPI_OFFICIAL_CHECKOUT_CAPTURE_FAILED}: "
        f"官方 Checkout 未找到可选的 UPI 支付方式：{detail}"
        f"；页面诊断={_upi_checkout_page_diagnostic(page)}"
    )


def _fill_upi_checkout_billing(page: Any, billing: dict[str, Any]) -> dict[str, Any]:
    """Fill the small set of billing fields required by UPI Checkout."""
    fields = (
        (
            "name",
            billing.get("name"),
            (
                'input[name="billingName"]',
                'input[name="name"]',
                'input[autocomplete="name"]',
                'input[id*="name" i]',
                'input[name*="name" i]',
            ),
        ),
        (
            "line1",
            billing.get("line1"),
            (
                'input[name="billingAddressLine1"]',
                'input[name="addressLine1"]',
                'input[autocomplete="address-line1"]',
                'input[name*="line1" i]',
                'input[id*="line1" i]',
            ),
        ),
        (
            "city",
            billing.get("city"),
            (
                'input[name="billingLocality"]',
                'input[name="locality"]',
                'input[autocomplete="address-level2"]',
                'input[name*="locality" i]',
                'input[name*="city" i]',
                'input[id*="city" i]',
            ),
        ),
        (
            "postal_code",
            billing.get("postal_code"),
            (
                'input[name="billingPostalCode"]',
                'input[name="postalCode"]',
                'input[autocomplete="postal-code"]',
                'input[name*="postal" i]',
                'input[name*="zip" i]',
                'input[id*="postal" i]',
                'input[id*="zip" i]',
            ),
        ),
        (
            "email",
            billing.get("email"),
            (
                'input[name="billingEmail"]',
                'input[name="email"]',
                'input[type="email"]',
                'input[autocomplete="email"]',
            ),
        ),
        (
            "phone",
            billing.get("phone"),
            (
                'input[name="billingPhone"]',
                'input[name="phone"]',
                'input[type="tel"]',
                'input[autocomplete="tel"]',
            ),
        ),
    )
    filled: dict[str, str] = {}
    for scope in _upi_page_frames(page):
        for key, value, selectors in fields:
            if key in filled or not str(value or "").strip():
                continue
            for selector in selectors:
                try:
                    locator = scope.locator(selector)
                    if locator.count() < 1 or not locator.first.is_visible():
                        continue
                    locator.first.scroll_into_view_if_needed(timeout=2_500)
                    locator.first.fill(str(value), timeout=4_000)
                    actual = str(locator.first.input_value(timeout=2_000) or "").strip()
                    if actual:
                        filled[key] = actual
                        break
                except Exception:
                    continue

        for selector in (
            'select[name="billingCountry"]',
            'select[name="billingCountryCode"]',
            'select#billingCountry',
            'select[autocomplete="country"]',
        ):
            try:
                locator = scope.locator(selector)
                if locator.count() < 1:
                    continue
                locator.first.select_option("IN", force=True, timeout=3_000)
                filled.setdefault("country", "IN")
                break
            except Exception:
                continue

    missing_required: list[str] = []
    for scope in _upi_page_frames(page):
        try:
            required = scope.locator('input[required], input[aria-required="true"]')
            for index in range(min(required.count(), 20)):
                item = required.nth(index)
                if not item.is_visible() or str(item.input_value(timeout=1_500) or "").strip():
                    continue
                identity = str(
                    item.get_attribute("name")
                    or item.get_attribute("id")
                    or item.get_attribute("autocomplete")
                    or ""
                ).strip()
                if identity and identity not in missing_required:
                    missing_required.append(identity)
        except Exception:
            continue
    return {
        "filled": sorted(filled),
        "missing_required": missing_required[:12],
    }


def _capture_upi_page_dom_candidates(page: Any) -> list[str]:
    """Read QR/instructions URLs exposed by the rendered official page."""
    candidates: list[str] = []
    script = """
    () => {
      const values = new Set();
      const attrs = ["src", "href", "data-url", "data-href", "data-qr-url", "data-payment-url"];
      for (const node of document.querySelectorAll("[src],[href],[data-url],[data-href],[data-qr-url],[data-payment-url],[data-testid],img,svg")) {
        for (const attr of attrs) {
          const value = node.getAttribute?.(attr);
          if (value) values.add(value);
        }
        if (node.currentSrc) values.add(node.currentSrc);
      }
      const html = document.documentElement?.outerHTML || "";
      for (const match of html.matchAll(/https?:\\/\\/[^"'<>\\s\\\\]+/g)) values.add(match[0]);
      return Array.from(values);
    }
    """
    for scope in _upi_page_frames(page):
        try:
            values = scope.evaluate(script)
        except Exception:
            continue
        if not isinstance(values, list):
            continue
        for value in values:
            candidate = str(value or "").strip().rstrip(".,;，；。")
            if not candidate:
                continue
            if (
                is_upi_instructions_url(candidate)
                or is_upi_qr_asset_url(candidate)
                or (is_qr_candidate(candidate) and not is_known_static_host(candidate))
            ):
                candidates.append(candidate)
    return list(dict.fromkeys(candidates))


def _upi_page_error_text(page: Any) -> str:
    """Collect visible error copy from the checkout page (declines / approval rejections)."""
    selectors = (
        '[role="alert"]',
        '[data-testid*="error" i]',
        '[aria-live="assertive"]',
        '[class*="Error" i]',
        '[class*="error" i]',
        '[id*="error" i]',
    )
    texts: list[str] = []
    for scope in _upi_page_frames(page):
        for selector in selectors:
            try:
                locator = scope.locator(selector)
                count = min(locator.count(), 3)
            except Exception:
                continue
            for index in range(count):
                try:
                    value = re.sub(
                        r"\s+", " ", str(locator.nth(index).inner_text(timeout=1_000) or "")
                    ).strip()
                except Exception:
                    continue
                if value and value not in texts:
                    texts.append(value[:160])
            if len(texts) >= 4:
                break
        if len(texts) >= 4:
            break
    return " | ".join(texts[:4])


def _session_cookie_parts_for(session: Any, domain: str) -> list[tuple[str, str]]:
    """Return ``(name, value)`` cookies already held for ``domain`` in the session jar."""
    jar = getattr(session, "cookies", None)
    if jar is None:
        return []
    base = str(domain or "").strip().lower().lstrip(".")
    if not base:
        return []
    try:
        items = list(jar)
    except Exception:
        return []
    parts: list[tuple[str, str]] = []
    for item in items:
        name = str(getattr(item, "name", "") or "").strip()
        value = str(getattr(item, "value") or "")
        cookie_domain = str(getattr(item, "domain", "") or "").strip().lower().lstrip(".")
        if not name or not cookie_domain:
            continue
        if base != cookie_domain and not base.endswith("." + cookie_domain):
            continue
        parts.append((name, value))
    return parts


def upi_session_host_cookies(
    session: Any,
    device_id: str,
    session_token: str,
) -> dict[str, str]:
    """Per-domain Cookie headers used when the hosted Checkout page is opened.

    托管结账页如果以「全新访客」身份打开，Stripe 会直接弹 hCaptcha。这里把本会话
    已经建立的 Cookie 身份按域带过去：ChatGPT 的会话 Cookie 只给 ``.chatgpt.com``，
    Stripe 域只带 Stripe 自己的 Cookie（``m`` / ``__stripe_mid`` 等），既不泄露账号
    令牌，也让托管页看到连续的访客身份。
    """
    mapping: dict[str, str] = {}
    chatgpt_parts: list[str] = []
    if str(device_id or "").strip():
        chatgpt_parts.append(f"oai-did={device_id}")
    if str(session_token or "").strip():
        chatgpt_parts.append(f"__Secure-next-auth.session-token={session_token}")
    if chatgpt_parts:
        mapping[".chatgpt.com"] = "; ".join(chatgpt_parts)
    stripe_parts = _session_cookie_parts_for(session, "stripe.com")
    if stripe_parts:
        mapping[".stripe.com"] = "; ".join(f"{name}={value}" for name, value in stripe_parts)
    return mapping


def capture_upi_qr_from_checkout_page(
    stripe: Any,
    checkout: dict[str, str],
    *,
    device_id: str,
    session_token: str,
    billing: dict[str, Any],
    fingerprint_profile: dict[str, Any] | None = None,
    target_url: str = "",
    approval_callback: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Fallback to the official/hosted Checkout UI when API confirm omits UPI links.

    ``target_url`` 默认是 ChatGPT 的 checkout 页；托管链补单模式会显式传入
    Stripe 托管结账页（``checkout.stripe.com/c/pay/cs_live_...#fidn...``）。
    """
    target_url = str(target_url or "").strip() or checkout_page_url(checkout)
    timeout_seconds = env_int("UPI_OFFICIAL_CHECKOUT_TIMEOUT", 45, minimum=10)
    timeout_ms = max(10_000, min(timeout_seconds * 1_000, 120_000))
    candidates: list[str] = []
    response_events: list[str] = []
    state: dict[str, Any] = {}
    network_state: dict[str, Any] = {"confirm_response": None}

    # 托管页要带着「本会话已经建立」的 Cookie 身份打开，否则会被当成全新访客直接
    # 触发 hCaptcha。Cookie 按域分开：ChatGPT 会话 Cookie 只给 chatgpt.com，
    # Stripe 域只带 Stripe 自己的 Cookie，避免把账号令牌泄露给 Stripe。
    host_cookies = upi_session_host_cookies(stripe, device_id, session_token)
    log(
        "官方 Checkout 打开前的 Cookie 身份："
        + (", ".join(sorted(host_cookies)) if host_cookies else "无"),
        "" if host_cookies else "[WARN] ",
    )

    def remember(value: Any) -> None:
        candidate = str(value or "").strip().rstrip(".,;，；。")
        if not candidate.startswith(("http://", "https://")):
            return
        if (
            is_upi_instructions_url(candidate)
            or is_upi_qr_asset_url(candidate)
            or (is_qr_candidate(candidate) and not is_known_static_host(candidate))
        ) and candidate not in candidates:
            candidates.append(candidate)
            if len(candidates) > 80:
                del candidates[:-80]

    def on_request(request: Any) -> None:
        try:
            remember(request.url)
        except Exception:
            pass

    def on_response(response: Any) -> None:
        try:
            remember(response.url)
            parsed = urlsplit(response.url)
            event = f"{int(response.status or 0)}:{(parsed.hostname or '').lower()}{parsed.path}"
            if event not in response_events:
                response_events.append(event)
                if len(response_events) > 24:
                    del response_events[:-24]
            try:
                method = str(response.request.method or "").upper()
            except Exception:
                method = ""
            host = (parsed.hostname or "").lower()
            if "hcaptcha.com" in host:
                # Stripe 用 hCaptcha 不可见模式做风控；记录命中次数用于识别软拦。
                network_state["hcaptcha_hits"] = int(
                    network_state.get("hcaptcha_hits") or 0
                ) + 1
            if method == "POST" and parsed.path.endswith("/confirm"):
                network_state["confirm_response"] = response
        except Exception:
            pass

    def on_frame_navigated(frame: Any) -> None:
        try:
            remember(frame.url)
        except Exception:
            pass

    def click_submit(page: Any) -> str:
        selectors = (
            '[data-testid="hosted-payment-submit-button"]',
            'button[type="submit"]',
            'button:has-text("Subscribe")',
            'button:has-text("Start trial")',
            'button:has-text("Confirm")',
            'button:has-text("Pay")',
            'button:has-text("Continue")',
            'button:has-text("Get Plus")',
            'button:has-text("开始试用")',
            'button:has-text("订阅")',
        )
        last_error = ""
        for frame_index, scope in enumerate(_upi_page_frames(page)):
            for selector in selectors:
                try:
                    locator = scope.locator(selector)
                    if locator.count() < 1 or not locator.first.is_visible():
                        continue
                    locator.first.scroll_into_view_if_needed(timeout=3_000)
                    locator.first.click(timeout=min(timeout_ms, 10_000))
                    return f"frame-{frame_index}:{selector}"
                except Exception as exc:
                    last_error = re.sub(r"\s+", " ", str(exc or "")).strip()[:180]
        raise RuntimeError(
            f"{UPI_OFFICIAL_CHECKOUT_CAPTURE_FAILED}: "
            f"官方 Checkout 未找到可点击的提交按钮：{last_error or 'submit button missing'}"
        )

    def workflow(page: Any) -> dict[str, Any]:
        page.on("request", on_request)
        page.on("response", on_response)
        page.on("framenavigated", on_frame_navigated)
        response = page.goto(
            target_url,
            wait_until="domcontentloaded",
            timeout=timeout_ms,
        )
        status = int(getattr(response, "status", 0) or 0) if response else 0
        if status >= 400:
            raise RuntimeError(
                f"{UPI_OFFICIAL_CHECKOUT_CAPTURE_FAILED}: "
                f"官方 Checkout 打开失败 HTTP {status}"
            )
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 8_000))
        except Exception:
            pass
        page.wait_for_timeout(700)
        remember(page.url)

        captcha_kind = _upi_hosted_captcha_kind(page)
        if captcha_kind:
            state["hosted_captcha"] = captcha_kind
            captcha_error = RuntimeError(
                f"{UPI_OFFICIAL_CHECKOUT_CAPTCHA}: 官方 Checkout 触发 {captcha_kind} "
                "人机验证，当前出口 IP / 指纹已被标记；本出口按失败计分，请换出口重试"
            )
            setattr(captcha_error, "capture_state", dict(state))
            raise captcha_error

        try:
            state["method_selector"] = _select_upi_payment_method(page, min(timeout_ms, 20_000))
        except Exception as select_exc:
            # Stripe Hosted 首屏偶尔只渲染 card，强制刷新一次才会带出 UPI；
            # 首轮找不到 UPI 时刷新重试一次，仍然没有才判失败。
            log(
                "官方 Checkout 首屏未找到 UPI 选项，刷新页面后重试："
                f"{str(select_exc)[:200]}",
                "[WARN] ",
            )
            try:
                page.reload(wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception as reload_exc:  # noqa: BLE001 - 刷新失败仍按原逻辑重试
                log(f"官方 Checkout 刷新失败，继续重试选择 UPI：{str(reload_exc)[:160]}", "[WARN] ")
            try:
                page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 8_000))
            except Exception:
                pass
            page.wait_for_timeout(800)
            captcha_kind = _upi_hosted_captcha_kind(page)
            if captcha_kind:
                state["hosted_captcha"] = captcha_kind
                captcha_error = RuntimeError(
                    f"{UPI_OFFICIAL_CHECKOUT_CAPTCHA}: 官方 Checkout 刷新后仍触发 "
                    f"{captcha_kind} 人机验证，当前出口 IP / 指纹已被标记；"
                    "本出口按失败计分，请换出口重试"
                )
                setattr(captcha_error, "capture_state", dict(state))
                raise captcha_error
            state["method_selector"] = _select_upi_payment_method(page, min(timeout_ms, 20_000))
        state["billing_before_submit"] = _fill_upi_checkout_billing(page, billing)
        page.wait_for_timeout(500)
        candidates.extend(_capture_upi_page_dom_candidates(page))
        state["submit_selector"] = click_submit(page)

        deadline = time.monotonic() + timeout_ms / 1_000
        submit_at = time.monotonic()
        refilled = False
        confirm_processed = False
        approval_processed = False
        while time.monotonic() < deadline:
            remember(page.url)
            candidates.extend(_capture_upi_page_dom_candidates(page))
            if (
                not state.get("hosted_confirm_submitted")
                and time.monotonic() - submit_at >= 6
            ):
                # 提交后迟迟没有 confirm 请求、页面又只回 Please try again：
                # 属于 Stripe 不可见 hCaptcha 的软拦，快速失败换出口。
                page_error = _upi_page_error_text(page)
                block_kind = _upi_hosted_risk_block_kind(
                    page,
                    int(network_state.get("hcaptcha_hits") or 0),
                    page_error,
                )
                if block_kind:
                    state["hosted_captcha"] = block_kind
                    state["page_error"] = page_error[:200]
                    risk_error = RuntimeError(
                        f"{UPI_OFFICIAL_CHECKOUT_CAPTCHA}: 官方 Checkout 被 Stripe 风控"
                        f"软拦（{block_kind}），点击提交后未产生 confirm 请求，"
                        f"页面提示={page_error[:80] or '-'}；当前出口 IP / 指纹已被标记，"
                        "本出口按失败计分，请换出口重试"
                    )
                    setattr(risk_error, "capture_state", dict(state))
                    raise risk_error
            confirm_response = network_state.get("confirm_response")
            if confirm_response is not None and not confirm_processed:
                confirm_processed = True
                try:
                    confirm_payload = confirm_response.json() or {}
                except Exception:
                    confirm_payload = {}
                submission = find_submission_attempt(confirm_payload)
                state["hosted_confirm_submitted"] = True
                state["hosted_confirm_http_status"] = int(
                    getattr(confirm_response, "status", 0) or 0
                )
                state["hosted_confirm_state"] = str(submission.get("state") or "")
                state["hosted_confirm_attempt_id"] = str(submission.get("id") or "")
                log_payment_page_summary("托管页面 confirm", confirm_payload)
                if (
                    state["hosted_confirm_state"] == "requires_approval"
                    and approval_callback is not None
                    and not approval_processed
                ):
                    approval_processed = True
                    log(
                        "托管页面 Confirm 已提交并进入 requires_approval，"
                        "开始调用 OpenAI approve 完成闭环..."
                    )
                    try:
                        approval_result = approval_callback(confirm_payload) or {}
                        state["hosted_approve_submitted"] = bool(
                            approval_result.get("approved", True)
                        )
                        state["hosted_approve_proxy"] = str(
                            approval_result.get("approve_proxy") or ""
                        )
                        deadline = max(
                            deadline,
                            time.monotonic() + max(12, min(timeout_seconds, 45)),
                        )
                        log("托管页面 OpenAI approve 已通过，继续等待 Stripe UPI instructions")
                    except Exception as exc:  # noqa: BLE001 - 页面仍可继续轮询/展示错误
                        state["hosted_approve_submitted"] = False
                        state["hosted_approve_error"] = re.sub(
                            r"\s+", " ", str(exc or "")
                        ).strip()[:240]
                        log(
                            "托管页面 OpenAI approve 未完成，继续观察 Stripe 页面："
                            f"{state['hosted_approve_error']}",
                            "[WARN] ",
                        )
            metadata = upi_capture_metadata(candidates)
            if metadata["upi_instructions_url"] or metadata["upi_qr_png"] or metadata["upi_qr_svg"]:
                break
            if (
                not refilled
                and not state.get("hosted_confirm_submitted")
                and time.monotonic() + 1.5 < deadline
            ):
                page.wait_for_timeout(1_000)
                refill = _fill_upi_checkout_billing(page, billing)
                state["billing_after_submit"] = refill
                if refill.get("filled") or refill.get("missing_required"):
                    try:
                        state["submit_retry_selector"] = click_submit(page)
                    except Exception:
                        pass
                refilled = True
            else:
                page.wait_for_timeout(600)

        candidates.extend(_capture_upi_page_dom_candidates(page))
        state["page_url"] = str(page.url or "")
        state["response_events"] = response_events[-12:]
        metadata = upi_capture_metadata(candidates)
        result_url = preferred_upi_result_url(
            str(metadata.get("upi_instructions_url") or ""),
            metadata["qr_urls"],
        )
        if not result_url:
            page_error = _upi_page_error_text(page)
            error = RuntimeError(
                f"{UPI_OFFICIAL_CHECKOUT_QR_NOT_FOUND}: "
                f"官方 Checkout 已提交但未捕获 UPI Instructions/QR；"
                f"confirm_state={state.get('hosted_confirm_state') or '-'}；"
                f"approve={'submitted' if state.get('hosted_approve_submitted') else state.get('hosted_approve_error') or '-'}；"
                f"page={state['page_url'][:180]}；"
                f"page_error={page_error or '-'}；"
                f"responses={','.join(response_events[-6:]) or '-'}"
            )
            setattr(error, "capture_state", dict(state))
            raise error
        metadata.update(state)
        metadata["official_checkout_capture"] = True
        metadata["result_url"] = result_url
        return metadata

    page_runner = stripe
    close_page_runner = False
    if not getattr(stripe, "is_browser_backed", False):
        proxy_url = str(
            (getattr(stripe, "proxies", {}) or {}).get("https")
            or (getattr(stripe, "proxies", {}) or {}).get("http")
            or ""
        ).strip()
        log("协议模式官方 Checkout 兜底：临时启动无头 Chromium")
        page_runner = new_session(
            proxy_url,
            use_pre_proxy=False,
            fingerprint_profile=fingerprint_profile,
            transport="headless",
        )
        try:
            for key, value in (getattr(stripe, "headers", {}) or {}).items():
                # Cookie 一律不整包复制：按域注入由 set_host_cookies 负责，
                # 否则会把 ChatGPT 会话 Cookie 发到 Stripe 域。
                if value is not None and str(key).lower() != "cookie":
                    page_runner.headers[str(key)] = str(value)
        except Exception:
            pass
        close_page_runner = True
    if host_cookies:
        setter = getattr(page_runner, "set_host_cookies", None)
        if callable(setter):
            try:
                setter(host_cookies)
            except Exception as exc:  # noqa: BLE001 - Cookie 注入失败不应中断流程
                log(f"官方 Checkout 注入会话 Cookie 失败：{str(exc)[:160]}", "[WARN] ")
    try:
        result = page_runner.run_page_workflow(
            target_url,
            workflow,
            timeout_ms=timeout_ms,
        )
    except RuntimeError as exc:
        text = str(exc)
        if text.startswith(
            (
                UPI_OFFICIAL_CHECKOUT_CAPTURE_FAILED,
                UPI_OFFICIAL_CHECKOUT_QR_NOT_FOUND,
                UPI_OFFICIAL_CHECKOUT_CAPTCHA,
                UPI_HEADLESS_BROWSER_LAUNCH_FAILED,
                UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED,
                UPI_HEADLESS_BROWSER_REQUEST_FAILED,
                UPI_HEADLESS_BROWSER_UNAVAILABLE,
            )
        ):
            raise
        raise RuntimeError(
            f"{UPI_OFFICIAL_CHECKOUT_CAPTURE_FAILED}: {text[:500]}"
        ) from exc
    finally:
        if close_page_runner:
            try:
                page_runner.close()
            except Exception:
                pass
    if not isinstance(result, dict):
        raise RuntimeError(
            f"{UPI_OFFICIAL_CHECKOUT_CAPTURE_FAILED}: 官方 Checkout 返回结果无效"
        )
    return result


def is_redirect_like_url(url: str, from_action_field: bool = False) -> bool:
    if not isinstance(url, str):
        return False
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return False
    if is_resource_url(url):
        return False
    if is_upi_instructions_url(url):
        return True
    if from_action_field:
        return True

    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    text = f"{host}{path}?{query}"
    if host in {"hooks.stripe.com", "payments.stripe.com"}:
        return True
    return any(part in text for part in ("upi", "/redirect/", "redirect_to_url", "authenticate"))


def is_qr_candidate(url: str) -> bool:
    lower = url.lower()
    return lower.startswith("data:image/") or "qr" in lower or "qrcode" in lower or "qr-code" in lower


def extract_qr_candidates(payload: Any) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for url in collect_urls(payload):
        if url in seen:
            continue
        seen.add(url)
        if is_qr_candidate(url) and not is_known_static_host(url):
            result.append(url)
    return result


def find_submission_attempt(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        value = payload.get("submission_attempt")
        if isinstance(value, dict):
            return value
        for item in payload.values():
            nested = find_submission_attempt(item)
            if nested:
                return nested
    elif isinstance(payload, list):
        for item in payload:
            nested = find_submission_attempt(item)
            if nested:
                return nested
    return {}


def submission_internal_error_code(submission: dict[str, Any]) -> str:
    """Return the checkout_approval_internal_error code when present."""
    if not isinstance(submission, dict):
        return ""
    error = submission.get("error")
    if isinstance(error, dict):
        return str(error.get("code") or "").strip()
    return ""


_DEAD_INTENT_STATUSES = ("requires_payment_method", "canceled")


def _iter_json_nodes(payload: Any, depth: int = 0) -> Any:
    """深度优先遍历嵌套 JSON（dict/list），逐个吐出节点。"""
    if depth > 8:
        return
    yield payload
    if isinstance(payload, dict):
        for value in payload.values():
            yield from _iter_json_nodes(value, depth + 1)
    elif isinstance(payload, list):
        for item in payload:
            yield from _iter_json_nodes(item, depth + 1)


def dead_upi_intent_reason(payload: Any) -> str:
    """返回非空字符串 = 这条链接是废链，不能交付。

    实测结论（对照 github.com/wangshen233/upi-zero-link 的 verify.py）：
    Stripe 在 setup_intent **被拒** 时仍会返回 hosted_instructions_url，
    只判断「有没有 URL」就会把废链交出去 —— 用户打开看到的是正价付款页。

    判据：intent 状态为 ``requires_payment_method`` / ``canceled``，
    且带 ``last_setup_error`` / ``last_payment_error``。
    注意 ``requires_payment_method`` 同时也是 SetupIntent 的初始状态，
    所以必须同时存在 last error 才算被拒。
    """
    for node in _iter_json_nodes(payload):
        if not isinstance(node, dict):
            continue
        for key in ("setup_intent", "payment_intent"):
            intent = node.get(key)
            if not isinstance(intent, dict):
                continue
            status = str(intent.get("status") or "").strip().lower()
            if status not in _DEAD_INTENT_STATUSES:
                continue
            error = intent.get("last_setup_error") or intent.get("last_payment_error")
            if not isinstance(error, dict):
                continue
            code = str(error.get("code") or "").strip()
            decline = str(error.get("decline_code") or "").strip()
            if not code and not decline:
                continue
            return (
                f"{key}.status={status} code={code or '-'} decline_code={decline or '-'}"
            )
    return ""


def is_submission_internal_failure(submission: dict[str, Any]) -> bool:
    """True when the submission failed server-side, not a payment/account decline."""
    if not isinstance(submission, dict):
        return False
    if str(submission.get("state") or "").strip().lower() != "failed":
        return False
    code = submission_internal_error_code(submission)
    if code != "checkout_approval_internal_error":
        return False
    error = submission.get("error")
    if isinstance(error, dict) and (error.get("decline_code") or error.get("payment_error")):
        return False
    return True


def submission_internal_error_detail(submission: dict[str, Any], limit: int = 420) -> str:
    """Compact error detail for a failed submission attempt.

    ``checkout_approval_internal_error`` 只给一个 code，日志里看不到
    message/type/decline_code 就无法判断是审批事务瞬时失败还是请求形态不对，
    所以这里把 error 对象里的关键字段抽出来。
    """
    if not isinstance(submission, dict):
        return ""
    error = submission.get("error")
    if not isinstance(error, dict):
        return ""
    parts: list[str] = []
    for key in ("code", "type", "message", "decline_code", "payment_error", "param", "doc_url"):
        value = error.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (dict, list)):
            text = json.dumps(value, ensure_ascii=False)
        else:
            text = str(value)
        # 不能在 f-string 表达式里写反斜杠（Python 3.10/3.11 会直接 SyntaxError），
        # 所以先归一化空白再拼串。
        normalized = re.sub(r"\s+", " ", text).strip()[:160]
        parts.append(f"{key}={normalized}")
    return "; ".join(parts)[:limit]


def extract_redirect_url(payload: Any, path: tuple[str, ...] = ()) -> str:
    if isinstance(payload, dict):
        next_action = payload.get("next_action")
        if isinstance(next_action, dict):
            hosted_instructions_url = str(next_action.get("hosted_instructions_url") or "").strip()
            if is_upi_instructions_url(hosted_instructions_url):
                return hosted_instructions_url
            redirect = next_action.get("redirect_to_url")
            if isinstance(redirect, dict):
                url = str(redirect.get("url") or "").strip()
                if is_redirect_like_url(url, True):
                    return url
            for key in ("url", "redirect_url", "redirect_to_url", "hosted_url", "hosted_instructions_url"):
                value = next_action.get(key)
                if is_redirect_like_url(value, True):
                    return value

        for key in (
            "hosted_instructions_url",
            "redirect_url",
            "redirect_to_url",
            "authorization_url",
            "authentication_url",
        ):
            value = payload.get(key)
            if is_redirect_like_url(value, True):
                return value

        for key, value in payload.items():
            nested = extract_redirect_url(value, path + (str(key),))
            if nested:
                return nested
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            nested = extract_redirect_url(item, path + (str(index),))
            if nested:
                return nested

    return ""


def first_value_by_key(payload: Any, key: str) -> Any:
    if isinstance(payload, dict):
        if key in payload:
            return payload[key]
        for value in payload.values():
            found = first_value_by_key(value, key)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = first_value_by_key(item, key)
            if found not in (None, "", [], {}):
                return found
    return None


def setup_intent_last_error(payload: Any, current_pm_id: str = "") -> str:
    if isinstance(payload, dict):
        payload_id = str(payload.get("id") or "").strip()
        is_setup_intent = payload.get("object") == "setup_intent" or payload_id.startswith("seti_")
        last_error = payload.get("last_setup_error") if is_setup_intent else None
        setup_intent = payload.get("setup_intent")
        if not last_error and isinstance(setup_intent, dict):
            last_error = setup_intent.get("last_setup_error")
        if last_error:
            if current_pm_id and isinstance(last_error, dict):
                error_pm = last_error.get("payment_method")
                error_pm_id = ""
                if isinstance(error_pm, dict):
                    error_pm_id = str(error_pm.get("id") or "").strip()
                elif isinstance(error_pm, str):
                    error_pm_id = error_pm.strip()
                if error_pm_id and error_pm_id != current_pm_id:
                    last_error = None
            if last_error:
                try:
                    return json.dumps(last_error, ensure_ascii=False)[:700]
                except Exception:
                    return str(last_error)[:700]
        for value in payload.values():
            found = setup_intent_last_error(value, current_pm_id=current_pm_id)
            if found:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = setup_intent_last_error(value, current_pm_id=current_pm_id)
            if found:
                return found
    return ""


def raise_if_setup_intent_blocked(payload: Any, context: str, current_pm_id: str = "") -> None:
    last_error = setup_intent_last_error(payload, current_pm_id=current_pm_id)
    if not last_error:
        return
    if "generic_decline" in last_error.lower():
        raise RuntimeError(f"Stripe 风控拒绝（generic_decline）：{context} SetupIntent 创建失败，未生成 redirect_url")
    raise RuntimeError(f"{context}: setup_intent.last_setup_error: {last_error}")


def should_retry_second_confirm_after_approve(error: Any) -> bool:
    text = str(error or "").lower()
    if is_terminal_approval_error(error):
        return False
    return (
        "checkout_upcoming_invoice_mismatch" in text
        or "redirect url resolution timeout" in text
        or "checkout_approval_internal_error" in text
        or "approve exception" in text
        or "missing_redirect" in text
    )


def stripe_intent_redirect_url(
    stripe: requests.Session,
    intent_payload: Any,
    stripe_pk: str,
    current_pm_id: str = "",
) -> str:
    if not isinstance(intent_payload, dict):
        return ""
    intent_id = str(intent_payload.get("id") or "").strip()
    client_secret = str(intent_payload.get("client_secret") or "").strip()
    if not intent_id or not client_secret:
        return ""
    intent_object = str(intent_payload.get("object") or "").strip()
    intent_path = "setup_intents" if intent_object == "setup_intent" or intent_id.startswith("seti_") else "payment_intents"
    params = {"key": stripe_pk, "client_secret": client_secret}
    url = f"https://api.stripe.com/v1/{intent_path}/{intent_id}"
    resp = stripe.get(url, params=params, timeout=DEFAULT_TIMEOUT)
    dump_http(resp, "stripe_intent_get", params, "GET", url, force=resp.status_code >= 400)
    if resp.status_code != 200:
        return ""
    try:
        payload = resp.json() or {}
    except Exception:
        payload = {"_raw_text": resp.text}
    raise_if_setup_intent_blocked(payload, "stripe intent", current_pm_id=current_pm_id)
    redirect_url = extract_redirect_url(payload)
    if redirect_url:
        dump_http(resp, "stripe_intent_redirect", params, "GET", url, force=True)
        log(f"读取 Stripe intent 拿到 redirect_url: {redirect_url[:180]}")
    return redirect_url


def stripe_payload_intent_redirect_url(
    stripe: requests.Session,
    payload: Any,
    stripe_pk: str,
    current_pm_id: str = "",
) -> str:
    if not isinstance(payload, dict):
        return ""
    for intent_key in ("setup_intent", "payment_intent"):
        candidates: list[Any] = []
        direct = payload.get(intent_key)
        if isinstance(direct, dict):
            candidates.append(direct)
        nested = first_value_by_key(payload, intent_key)
        if isinstance(nested, dict) and all(nested is not item for item in candidates):
            candidates.append(nested)
        for intent_payload in candidates:
            redirect_url = stripe_intent_redirect_url(stripe, intent_payload, stripe_pk, current_pm_id=current_pm_id)
            if redirect_url:
                return redirect_url
    return ""


def infer_processor_entity(payload: Any) -> str:
    for value in collect_strings(payload):
        match = re.search(r"[?&]processor_entity=([A-Za-z0-9_]+)", value)
        if match:
            return match.group(1)
    return ""


def payment_page_summary(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    elements_options = payload.get("elements_options") if isinstance(payload.get("elements_options"), dict) else {}
    submission = find_submission_attempt(payload)
    next_action = first_value_by_key(payload, "next_action")
    payment_intent = first_value_by_key(payload, "payment_intent")
    setup_intent = first_value_by_key(payload, "setup_intent")
    summary: dict[str, Any] = {
        "object": payload.get("object"),
        "id": payload.get("id"),
        "status": payload.get("status"),
        "payment_status": payload.get("payment_status"),
        "amount": elements_options.get("amount") if elements_options else first_value_by_key(payload, "amount"),
        "currency": payload.get("currency") or (elements_options.get("currency") if elements_options else None),
        "mode": elements_options.get("mode") if elements_options else payload.get("mode"),
        "payment_method_types": elements_options.get("payment_method_types") if elements_options else None,
        "submission_state": submission.get("state") if submission else None,
        "submission_status": submission.get("status") if submission else None,
        "has_next_action": isinstance(next_action, dict) and bool(next_action),
    }
    if isinstance(payment_intent, dict):
        summary["payment_intent_status"] = payment_intent.get("status")
    elif isinstance(payment_intent, str):
        summary["payment_intent"] = payment_intent
    if isinstance(setup_intent, dict):
        summary["setup_intent_status"] = setup_intent.get("status")
    elif isinstance(setup_intent, str):
        summary["setup_intent"] = setup_intent
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def log_payment_page_summary(stage: str, payload: Any) -> None:
    summary = payment_page_summary(payload)
    if not summary:
        return
    compact = format_payment_summary(summary)
    log(f"{stage} 返回摘要: {compact}")


def format_payment_summary(summary: dict[str, Any]) -> str:
    return ", ".join(f"{key}={value}" for key, value in summary.items())


def warmup_approve_context(chatgpt: requests.Session, checkout_page_url: str) -> None:
    try:
        resp = chatgpt.post(
            "https://chatgpt.com/backend-api/sentinel/ping",
            json={},
            headers={
                "Referer": "https://chatgpt.com/",
                "x-openai-target-path": "/backend-api/sentinel/ping",
                "x-openai-target-route": "/backend-api/sentinel/ping",
            },
            timeout=CHATGPT_TIMEOUT,
        )
        dump_http(resp, "sentinel_ping", {}, "POST", "https://chatgpt.com/backend-api/sentinel/ping", force=env_bool("UPI_DUMP_WARMUP", False))
    except Exception as exc:
        log(f"approve sentinel 请求异常: {exc}", "[WARN] ")


def chatgpt_approve(chatgpt: requests.Session, checkout: dict[str, str]) -> None:
    cs_id = checkout["cs_id"]
    processor = processor_entity_for_country(checkout.get("billing_country", "IN"), checkout.get("processor_entity", ""))
    checkout_page_url = f"https://chatgpt.com/checkout/{processor}/{cs_id}"
    if env_bool("UPI_APPROVE_WARMUP", True):
        warmup_approve_context(chatgpt, checkout_page_url)
        time.sleep(random.uniform(0.8, 1.6))

    body = {"checkout_session_id": cs_id, "processor_entity": processor}
    headers = {
        "Referer": checkout_page_url,
        "x-openai-target-path": "/backend-api/payments/checkout/approve",
        "x-openai-target-route": "/backend-api/payments/checkout/approve",
    }
    ensure_upi_sentinel(
        chatgpt,
        flow="checkout_session_approval",
        page_url=checkout_page_url,
    )
    log("UPI approve 使用 OpenAI Sentinel 会话上下文")
    resp = chatgpt.post(
        "https://chatgpt.com/backend-api/payments/checkout/approve",
        json=body,
        headers=headers,
        timeout=CHATGPT_TIMEOUT,
    )
    dump_http(resp, "approve", body, "POST", "https://chatgpt.com/backend-api/payments/checkout/approve", force=True)
    if resp.status_code >= 400:
        raise RuntimeError(f"ChatGPT approve 失败 HTTP {resp.status_code}: {resp.text[:300]}")
    result = ""
    try:
        result = str((resp.json() or {}).get("result") or "").strip().lower()
    except Exception:
        pass
    if result != "approved":
        raise RuntimeError(f"ChatGPT approve 未通过: {result or resp.text[:200]}")


def approve_confirm_first_enabled(checkout: dict[str, Any]) -> bool:
    """Whether ``/checkout/confirm`` can be tried before ``/approve``.

    The confirm endpoint only serves OpenAI internal checkout sessions; Stripe
    sessions answer ``400 {"detail":"This endpoint is only for internal
    checkout sessions"}``. So the default ``auto`` mode only tries confirm for
    internal sessions (``oaics_``), and never wastes a request per approve
    attempt on ``cs_live_`` sessions.

    Values: ``auto`` (default), ``1`` force try, ``0`` disable.
    """
    mode = str(os.environ.get("UPI_APPROVE_CONFIRM_FIRST", "auto")).strip().lower()
    if mode in {"0", "false", "no", "off"}:
        return False
    if mode in {"1", "true", "yes", "on"}:
        return True
    return str(checkout.get("cs_id") or "").strip().startswith("oaics_")


def approve_attempt(
    access_token: str,
    device_id: str,
    checkout: dict[str, str],
    session_token: str,
    proxy: str,
    index: int,
    attempt_count: int,
    fingerprint_profile: dict[str, Any] | None = None,
) -> None:
    log(f"approve 第 {index}/{attempt_count} 次 / proxy={proxy_label(proxy)}")
    chatgpt = build_chatgpt_session(
        access_token,
        device_id,
        proxy,
        session_token,
        fingerprint_profile=fingerprint_profile,
    )
    if approve_confirm_first_enabled(checkout):
        # 对齐开源实现：/checkout/confirm 也能直接返回 {"result":"approved"}，
        # 命中就省掉一次 approve 风控判定。该端点不参与 Sentinel 校验，
        # 因此不动会话级 Sentinel 头（保持与真实网页端请求一致）。
        try:
            cs_id = str(checkout.get("cs_id") or "").strip()
            processor = processor_entity_for_country(
                checkout.get("billing_country", UPI_BOOTSTRAP_COUNTRY),
                checkout.get("processor_entity") or "",
            )
            checkout_page_url = f"https://chatgpt.com/checkout/{processor}/{cs_id}"
            route = "/backend-api/payments/checkout/confirm"
            resp = chatgpt.post(
                f"https://chatgpt.com{route}",
                json={
                    "checkout_session_id": cs_id,
                    "selected_payment_method_type": "upi",
                },
                headers={
                    "Referer": checkout_page_url,
                    "x-openai-target-path": route,
                    "x-openai-target-route": route,
                    "Accept": "application/json",
                },
                timeout=CHATGPT_TIMEOUT,
            )
            dump_http(
                resp,
                "approve_confirm_first",
                None,
                "POST",
                f"https://chatgpt.com{route}",
                force=(index == 1),
            )
            if resp.status_code >= 400:
                if resp.status_code in {401, 403, 429}:
                    raise RuntimeError(f"ChatGPT approve confirm 失败 HTTP {resp.status_code}")
                log(
                    f"confirm 端点 HTTP {resp.status_code}（{str(resp.text or '')[:120]}），改用 approve 端点",
                    "[WARN] ",
                )
            else:
                payload = resp.json() or {}
                result = str(payload.get("result") or payload.get("status") or "").strip().lower()
                if result == "approved":
                    log("approve 已通过 confirm 端点（result=approved）")
                    return
                if result in {"blocked", "expired", "exception", "declined", "rejected"}:
                    raise RuntimeError(f"ChatGPT approve 未通过: {result}")
                log(f"confirm 端点未直接通过（result={result or '-'}），改用 approve 端点", "[WARN] ")
        except Exception as exc:  # noqa: BLE001 - confirm-first is best effort
            if is_terminal_approval_error(exc):
                raise
            log(f"confirm 端点尝试异常，改用 approve 端点：{str(exc)[:140]}", "[WARN] ")
    chatgpt_approve(chatgpt, checkout)


def log_approve_failure(error: str, proxy: str = "") -> bool:
    log(f"approve 失败: {error[:180]}", "[WARN] ")
    if "ChatGPT approve 未通过: blocked" in error:
        log(
            "approve 返回 blocked：记入出口 block 计数（不记为「代理故障」），"
            "窗口内再次命中同一出口将被临时停用",
            "[WARN] ",
        )
        record_exit_risk_block(proxy, error)
        return True
    if "ChatGPT approve 未通过: expired" in error:
        log(
            "approve 返回 expired：该 checkout 审批窗口已过期，"
            "重建新 Checkout 才有可能重新获得审批窗口",
            "[WARN] ",
        )
        return False
    if is_approve_transaction_exception_error(error):
        log(
            "approve 返回 exception：该 Checkout 的审批事务已进入异常态"
            "（通常紧跟在 checkout_approval_internal_error 之后），"
            "同一 Checkout 继续 approve 不会再回到 approved，只会计入风控",
            "[WARN] ",
        )
        return False
    return False


def is_approve_failure_error(error: str) -> bool:
    text = str(error or "").lower()
    return "approve" in text or "chatgpt approve" in text


_ACCOUNT_LEVEL_FAILURE_MARKERS = (
    # OpenAI 人工审批拒绝：账号风控，换出口不改变判定
    "approve blocked",
    "approve 未通过: blocked",
    "chatgpt approve 未通过",
    # 促销/试用对该号不生效：金额压不到 0
    "upi_amount_nonzero",
    # 0 元资格预检未通过
    "upi_zero_ineligible",
    # Stripe 明确拒绝建立委托（参考实现标注为「该号零元资格已耗尽」）
    "generic_decline",
    "setupintent 创建失败",
    "setup_intent 创建失败",
    # approve 之后的实际扣款被渠道拒（账号/渠道级）
    "payment_method_provider_decline",
    "checkout_approval_payment_failure_with_payment_error",
)


def is_account_level_failure(error: Any) -> bool:
    """账号级失败：换出口/换指纹不会改变判定，应当停止该账号剩余轮次。

    与之相对的是**出口层失败**（TLS 握手、连接超时、连接重置、代理认证），
    那类失败换一条出口就有机会恢复，必须继续多轮重试。
    判定只认上面这些明确的账号/渠道信号，绝不把传输层错误算进来。
    """
    text = str(error or "").lower()
    if not text:
        return False
    return any(marker in text for marker in _ACCOUNT_LEVEL_FAILURE_MARKERS)


def is_account_level_original_price_failure(error: Any) -> bool:
    """True when a 原价链 run was pushed into the 0 元 approval flow.

    这属于账号级判定（该账号在正价链路上仍被判成 0 元），换出口/换指纹都救不回来，
    因此应当立即停止同号的整链重试，避免继续烧代理与 CDK。
    """
    return UPI_ORIGINAL_PRICE_APPROVAL_REQUIRED in str(error or "")


def is_approve_expired_error(error: Any) -> bool:
    """True when OpenAI answered the approve call with result=expired."""
    return "approve 未通过: expired" in str(error or "")


def is_approve_transaction_exception_error(error: Any) -> bool:
    """True when OpenAI answered the approve call with result=exception.

    实测（2026-09-20，dr 域名 0 元样本）：一旦某个 Checkout 在 approve 后返回
    ``checkout_approval_internal_error``，同一 Checkout 后续 approve 只会拿到
    ``exception``（持续 10/10），并逐步把账号推向 ``blocked``。因此命中
    ``exception`` 应当直接放弃当前 Checkout 交给外层重建，而不是把
    ``UPI_APPROVE_CYCLES × UPI_APPROVE_ATTEMPTS_PER_CYCLE`` 打完。
    """
    return "approve 未通过: exception" in str(error or "")


def is_rate_limited_error(error: Any) -> bool:
    text = str(error or "").lower()
    return any(marker in text for marker in ("http 429", "upi_rate_limited", "rate_limit", "too many requests"))


def is_terminal_approval_error(error: Any) -> bool:
    """明确拒绝、审批过期、认证失败或限流，不能靠重复提交恢复。"""
    text = str(error or "").lower()
    return (
        is_rate_limited_error(error)
        or is_approve_expired_error(error)
        or is_approve_transaction_exception_error(error)
        or any(marker in text for marker in (
            "approve blocked", "approve 未通过: blocked",
            "approve exception",
            "approve 未通过: declined", "approve 未通过: rejected",
            "http 401", "http 403",
        ))
    )


def poll_retry_delay(response: Any, failures: int) -> float:
    """只读轮询遵守 Retry-After；缺失或无效时使用有抖动的指数退避。"""
    headers = getattr(response, "headers", {}) or {}
    value = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    if value:
        try:
            seconds = float(value)
        except ValueError:
            try:
                seconds = parsedate_to_datetime(value).timestamp() - time.time()
            except (ValueError, TypeError, OverflowError):
                seconds = -1
        if math.isfinite(seconds) and seconds > 0:
            return seconds
    return min(30.0, 2.0 ** min(max(failures, 1), 5)) + random.uniform(0, 1)


def approve_with_retry(
    access_token: str,
    device_id: str,
    checkout: dict[str, str],
    proxies: list[str],
    session_token: str,
    proxy_group: str = "provider",
    fingerprint_profile: dict[str, Any] | None = None,
) -> str:
    max_retry = env_int("UPI_APPROVE_RETRY_MAX", 10)
    parallel = env_int("UPI_APPROVE_PARALLEL", 1)
    last_error = ""
    if max_retry <= 0:
        raise RuntimeError("approve 重试次数必须大于 0")
    proxies = [proxy for proxy in dict.fromkeys(proxies) if proxy]
    if not proxies:
        raise RuntimeError("approve 代理为空")
    sticky = env_bool("UPI_APPROVE_STICKY", True)
    if parallel > 1:
        log("同一 Checkout 的审批操作固定串行，避免并发重复提交")
    if sticky:
        selected_proxies = proxies[:max_retry]
    else:
        attempt_count = min(max_retry, len(proxies))
        fixed_proxies = proxies[: min(2, attempt_count)]
        selected_proxies = fixed_proxies[:]
        remain_count = attempt_count - len(selected_proxies)
        if remain_count > 0:
            selected_proxies.extend(random.sample(proxies[2:], min(remain_count, len(proxies) - 2)))
    attempt_count = len(selected_proxies)
    # 轮数只控制瞬时传输故障的重试预算；明确拒绝立即停止，不重复碰审批。
    cycles = env_int("UPI_APPROVE_CYCLES", 5, minimum=1)
    per_cycle = env_int("UPI_APPROVE_ATTEMPTS_PER_CYCLE", 2, minimum=1)
    planned_total = min(max_retry, cycles * per_cycle)
    planned: list[str] = []
    while len(planned) < planned_total:
        planned.extend(selected_proxies)
    planned = planned[:planned_total]
    attempt_count = len(planned)
    log(
        f"approve 代理策略: {'sticky' if sticky else 'rotate'}；"
        f"计划 {cycles} 轮 × {per_cycle} 次 = {attempt_count} 次（每轮重新 mint sentinel）"
    )
    for index, proxy in enumerate(planned, start=1):
        try:
            approve_attempt(
                access_token,
                device_id,
                checkout,
                session_token,
                proxy,
                index,
                attempt_count,
                fingerprint_profile,
            )
            log("approve 成功")
            return proxy
        except Exception as exc:
            last_error = str(exc)
            if is_checkout_not_active_error(last_error):
                raise RuntimeError("checkout_not_active_session")
            log_approve_failure(last_error, proxy)
            if is_terminal_approval_error(last_error):
                log("审批已明确拒绝、失效或限流：停止当前 Checkout 的剩余审批请求", "[WARN] ")
                raise RuntimeError(last_error) from exc
            if index < attempt_count:
                time.sleep(min(8.0, 2.0 ** min(index - 1, 3)) + random.uniform(0, 1))
    raise RuntimeError(f"approve 重试失败: {last_error}")


def poll_payment_page(
    stripe: requests.Session,
    checkout: dict[str, str],
    stripe_pk: str,
    ctx: dict[str, Any],
    current_pm_id: str = "",
    reapprove: Callable[[], None] | None = None,
) -> tuple[str, list[str]]:
    cs_id = checkout["cs_id"]
    # 对齐开源实现：poll 窗口放宽到 ~100s（40×2.5s），给审批/跳转更多落地时间。
    deadline = time.time() + env_int("UPI_POLL_TIMEOUT", 100)
    # 0 元链路里 approve 已返回 approved、但 OpenAI 审批事务瞬时失败时，
    # 服务端只回 checkout_approval_internal_error。此时重新 approve 会生成
    # 新的 cs_attempt，比干等 poll 超时更有机会拿到 instructions 链接。
    reapprove_max = env_int("UPI_POLL_INTERNAL_ERROR_REAPPROVE_MAX", 3, minimum=0)
    extend_seconds = env_int("UPI_POLL_INTERNAL_ERROR_EXTEND", 20, minimum=0)
    extend_cap = env_int("UPI_POLL_INTERNAL_ERROR_EXTEND_CAP", 60, minimum=0)
    reapprove_count = 0
    extended = 0.0
    last_reapprove_at = 0.0
    internal_detail_logged = False
    params = {
        **stripe_elements_session_params(ctx),
        "key": stripe_pk,
        "_stripe_version": str(ctx.get("stripe_version") or STRIPE_VERSION_FULL),
    }
    url = f"https://api.stripe.com/v1/payment_pages/{cs_id}"
    last_error = ""
    last_payload: dict[str, Any] = {}
    last_summary = ""
    http_failures = 0
    while time.time() < deadline:
        resp = stripe.get(url, params=params, timeout=DEFAULT_TIMEOUT)
        if resp.status_code >= 400:
            dump_http(resp, "poll_error", params, "GET", url, force=True)
            if is_checkout_not_active_error(resp.text):
                raise RuntimeError("checkout_not_active_session")
            last_error = f"HTTP {resp.status_code}"
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                raise RuntimeError(f"Stripe payment_pages poll 失败: {last_error}")
            http_failures += 1
            delay = poll_retry_delay(resp, http_failures)
            remaining = deadline - time.time()
            if delay >= remaining:
                prefix = "UPI_RATE_LIMITED" if resp.status_code == 429 else "UPI_POLL_UPSTREAM_ERROR"
                raise RuntimeError(f"{prefix}: {last_error}，上游要求等待时间超过本次轮询窗口")
            log(f"payment_pages {last_error}，退避 {delay:.1f}s 后继续只读轮询", "[WARN] ")
            time.sleep(delay)
            continue
        http_failures = 0
        try:
            payload = resp.json() or {}
        except Exception:
            payload = {"_raw_text": resp.text}
        raise_if_setup_intent_blocked(payload, "stripe payment_pages", current_pm_id=current_pm_id)
        last_payload = payload
        summary = payment_page_summary(payload)
        summary_text = format_payment_summary(summary) if summary else ""
        if summary_text and summary_text != last_summary:
            last_summary = summary_text
            log(f"poll 返回摘要: {summary_text}")
        # 先判 intent 是否已被拒：被拒时 Stripe 仍会给出 hosted_instructions_url，
        # 直接返回就等于把废链交付出去（用户打开看到正价付款页）。
        dead = dead_upi_intent_reason(payload)
        if dead:
            dump_http(resp, "poll_dead_intent", params, "GET", url, force=True)
            raise RuntimeError(f"UPI intent 已被拒（废链，不交付）: {dead}")
        redirect_url = extract_redirect_url(payload)
        qr_urls = extract_qr_candidates(payload)
        if redirect_url or qr_urls:
            dump_http(resp, "poll_success", params, "GET", url, force=True)
            return redirect_url, qr_urls
        intent_redirect = stripe_payload_intent_redirect_url(stripe, payload, stripe_pk, current_pm_id=current_pm_id)
        if intent_redirect:
            dump_http(resp, "poll_success", params, "GET", url, force=True)
            return intent_redirect, qr_urls
        submission = find_submission_attempt(payload)
        if submission.get("state") == "requires_approval":
            last_error = "payment_pages 仍然 requires_approval"
            time.sleep(1)
            continue
        if submission.get("state") == "failed":
            if is_submission_internal_failure(submission):
                # approve 已返回 approved，但 OpenAI/Stripe 在最终审批事务上
                # 返回 checkout_approval_internal_error（decline/payment_error
                # 均为空）。这类失败可能只是瞬时状态，继续在窗口内轮询，
                # 等待新的 submission attempt / requires_approval / redirect。
                last_error = f"checkout_approval_internal_error: {submission.get('id') or ''}"
                if not internal_detail_logged:
                    internal_detail_logged = True
                    detail = submission_internal_error_detail(submission)
                    log(
                        "checkout_approval_internal_error 详情: "
                        f"{detail or 'upstream 未返回 error.message'}；"
                        "原始 submission="
                        + json.dumps(submission, ensure_ascii=False)[:900],
                        "[WARN] ",
                    )
                now = time.time()
                should_reapprove = (
                    reapprove is not None
                    and reapprove_count < reapprove_max
                    and now - last_reapprove_at >= 4
                )
                if should_reapprove:
                    reapprove_count += 1
                    last_reapprove_at = now
                    if extend_seconds > 0 and extended < extend_cap:
                        bonus = min(extend_seconds, extend_cap - extended)
                        deadline += bonus
                        extended += bonus
                    log(
                        "poll 观察到 checkout_approval_internal_error（非支付拒绝），"
                        f"第 {reapprove_count}/{reapprove_max} 次重新 approve 后再观察："
                        f"{last_error[:160]}",
                        "[WARN] ",
                    )
                    try:
                        reapprove()
                        log("重新 approve 已提交，继续轮询等待新审批结果")
                    except Exception as exc:  # noqa: BLE001 - 保持轮询语义
                        if is_terminal_approval_error(exc):
                            raise
                        log(f"重新 approve 失败，继续观察：{str(exc)[:160]}", "[WARN] ")
                else:
                    log(
                        "poll 观察到 checkout_approval_internal_error（非支付拒绝），继续观察："
                        f"{last_error[:160]}",
                        "[WARN] ",
                    )
                time.sleep(1.5)
                continue
            dump_http(resp, "poll_failed", params, "GET", url, force=True)
            raise RuntimeError(f"Stripe submission failed: {submission}")
        last_error = str(submission or "waiting")
        time.sleep(1)
    if last_payload:
        dump_response = type("DumpResponse", (), {})()
        dump_response.status_code = 200
        dump_response.url = url
        dump_response.text = json.dumps(last_payload, ensure_ascii=False, indent=2)
        dump_http(dump_response, "poll_no_redirect", params, "GET", url, force=True)
    log(f"poll 结束，未发现真实 UPI redirect/QR: {last_error}", "[WARN] ")
    raise RuntimeError(f"redirect url resolution timeout: {last_error}")


def fetch_redirect_page(stripe: requests.Session, start_url: str) -> list[str]:
    if not start_url or not env_bool("UPI_FOLLOW_REDIRECT", True):
        return []
    current = start_url
    qr_urls: list[str] = []
    for hop in range(1, 6):
        resp = stripe.get(current, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        dump_http(resp, f"redirect_hop_{hop}", None, "GET", current, force=True)
        qr_urls.extend(extract_qr_candidates(resp.text))
        location = resp.headers.get("location") or resp.headers.get("Location") or ""
        if not location:
            break
        current = urljoin(current, location)
    return list(dict.fromkeys(qr_urls))


def resolve_external_redirect(stripe: requests.Session, start_url: str) -> str:
    if not start_url or not env_bool("UPI_FOLLOW_REDIRECT", True):
        return start_url
    current = start_url
    for hop in range(1, 6):
        if is_upi_instructions_url(current):
            return current
        try:
            resp = stripe.get(current, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            dump_http(resp, f"resolve_redirect_hop_{hop}", None, "GET", current, force=True)
        except Exception as exc:
            log(f"跟随 redirect 异常: {exc}", "[WARN] ")
            return current
        location = resp.headers.get("location") or resp.headers.get("Location") or ""
        if not location:
            return current
        current = urljoin(current, location)
    return current


def approve_proxy_candidates(checkout_proxy: str, provider_proxy: str, approve_pool: list[str]) -> list[str]:
    approve_preferences = successful_approve_preferences(checkout_proxy, provider_proxy, [provider_proxy] + approve_pool)
    if approve_preferences:
        log(f"命中成功 approve 代理优先: {proxy_label(approve_preferences[0])}")
    return list(dict.fromkeys(approve_preferences + [provider_proxy] + approve_pool))


def resolve_confirm_payload_upi(
    stripe: requests.Session,
    confirm_payload: dict[str, Any],
    checkout: dict[str, str],
    stripe_pk: str,
    ctx: dict[str, Any],
    pm_id: str,
    access_token: str,
    device_id: str,
    session_token: str,
    checkout_proxy: str,
    provider_proxy: str,
    approve_pool: list[str],
    fingerprint_profile: dict[str, Any] | None = None,
) -> tuple[str, list[str], str]:
    raise_if_setup_intent_blocked(confirm_payload, "stripe confirm", current_pm_id=pm_id)
    redirect_url = extract_redirect_url(confirm_payload)
    if not redirect_url:
        redirect_url = stripe_payload_intent_redirect_url(stripe, confirm_payload, stripe_pk, current_pm_id=pm_id)
    qr_urls = extract_qr_candidates(confirm_payload)
    submission = find_submission_attempt(confirm_payload)

    if redirect_url:
        log(f"confirm 提取到最终支付 URL: {redirect_url[:180]}")
    if qr_urls:
        log(f"confirm 提取到 QR 候选 {len(qr_urls)} 个")

    approve_proxy = ""
    approve_proxies = approve_proxy_candidates(checkout_proxy, provider_proxy, approve_pool)

    def reapprove() -> str:
        return approve_with_retry(
            access_token,
            device_id,
            checkout,
            approve_proxies,
            session_token,
            "provider",
            fingerprint_profile,
        )

    if not redirect_url and submission.get("state") == "requires_approval":
        # UPI 链路固定携带 checkout_manual_approval_preview=v1，OpenAI 对每一笔 UPI
        # 订阅都会返回 requires_approval —— 这是固有的审批步骤，与金额是否为 0 无关。
        # 线上实测：1513/1513 次 confirm 全部 requires_approval，其中 59 次金额为正价
        # INR 1999，且正价场景 approve 成功率约 86%。因此原价链同样必须走 approve，
        # 否则正价链永远拿不到 instructions。
        #
        # 真正的 0 元判定只看金额：原价链若被上游把金额压到 0（OpenAI 按账号试用资格
        # 自动折扣，实测 mode=off 建单金额仍为 0，与链路是否注入 promo 无关），
        # approve 通过后交付的仍是 0 元链。默认直接判失败，管理员可用
        # UPI_ORIGINAL_PRICE_ZERO_FALLBACK=1 允许降级交付并在结果里标记。
        if (
            not chain_requires_zero()
            and int(ctx.get("checkout_amount") or 0) == 0
            and not original_price_zero_fallback_enabled()
        ):
            raise RuntimeError(
                f"{UPI_ORIGINAL_PRICE_APPROVAL_REQUIRED}: 原价链被上游压成 0 元："
                "OpenAI 按该账号的 0 元试用/满减资格自动把 checkout 金额判为 0"
                "（实测 mode=off 建单金额仍为 0，与链路是否注入优惠无关）。"
                "该账号无法产出正价 UPI 链；请更换无试用/折扣资格的账号走原价链，"
                "或改用 0 元链。"
                f"（checkout={checkout.get('cs_id', '')[:24]}，amount=0）"
            )
        log("需要 ChatGPT approve...")
        log(
            f"需要 approve：UPI {chain_kind_label()}，"
            "优先使用历史成功/当前 Provider 代理，失败后切换下一个 Provider 代理。"
        )
        approve_proxy = reapprove()
        log("跟随跳转提取最终链...")
        redirect_url, poll_qr = poll_payment_page(
            stripe,
            checkout,
            stripe_pk,
            ctx,
            current_pm_id=pm_id,
            reapprove=reapprove,
        )
        qr_urls.extend(poll_qr)
    elif not redirect_url and not qr_urls:
        log("confirm 未返回真实 UPI redirect/QR，继续 poll payment_pages 做最终确认", "[WARN] ")
        redirect_url, poll_qr = poll_payment_page(
            stripe,
            checkout,
            stripe_pk,
            ctx,
            current_pm_id=pm_id,
            reapprove=reapprove,
        )
        qr_urls.extend(poll_qr)

    return redirect_url, list(dict.fromkeys(qr_urls)), approve_proxy


def complete_hosted_checkout_in_browser(
    stripe: Any,
    checkout: dict[str, Any],
    hosted_url: str,
    *,
    device_id: str,
    session_token: str,
    billing: dict[str, Any],
    fingerprint_profile: dict[str, Any] | None = None,
    reason: Any = "",
    approval_callback: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """托管链补单模式（半自动）：用无头指纹浏览器在托管结账页完成最后一步。

    打开 ``checkout.stripe.com/c/pay/cs_live_...``（或 ``pay.openai.com`` 托管页），
    自动填账单地址 → 选 UPI → 点订阅，然后抓取 instructions/二维码。
    成功返回 ``{"url":..., "qr_urls":[...]}``；失败/未开启返回 ``{"error": "..."}``。

    默认关闭（``UPI_HOSTED_COMPLETE=0``）：无头浏览器很吃服务器资源，
    由管理员在后台按需开启，方便和纯协议链路做 A/B。
    """
    if not env_bool("UPI_HOSTED_COMPLETE", False):
        return {"enabled": False, "error": "UPI_HOSTED_COMPLETE=0"}
    url = str(hosted_url or "").strip()
    if not url.startswith(("http://", "https://")):
        return {"enabled": False, "error": "hosted url missing"}
    try:
        captured = capture_upi_qr_from_checkout_page(
            stripe,
            checkout,
            device_id=device_id,
            session_token=session_token,
            billing=billing,
            fingerprint_profile=fingerprint_profile,
            target_url=url,
            approval_callback=approval_callback,
        )
    except Exception as exc:  # noqa: BLE001 - 补单失败要回落到托管链交付
        # 页面诊断包含 title/frames/可见支付选项，截断到 200 就看不到关键信息了。
        detail = re.sub(r"\s+", " ", str(exc or "")).strip()[:900]
        capture_state = getattr(exc, "capture_state", {})
        if not isinstance(capture_state, dict):
            capture_state = {}
        log(f"托管链补单失败，回落到人工完成模式：{detail}", "[WARN] ")
        return {
            "enabled": True,
            "error": detail,
            # 人机验证拦截：调用方据此把这个出口记成 captcha 失败，下次换出口。
            "captcha": str(capture_state.get("hosted_captcha") or ""),
            "confirm_submitted": bool(capture_state.get("hosted_confirm_submitted")),
            "confirm_state": str(capture_state.get("hosted_confirm_state") or ""),
            "confirm_attempt_id": str(capture_state.get("hosted_confirm_attempt_id") or ""),
            "approve_submitted": bool(capture_state.get("hosted_approve_submitted")),
            "approve_error": str(capture_state.get("hosted_approve_error") or "")[:200],
        }
    result_url = str(captured.get("result_url") or "").strip()
    if not result_url:
        return {
            "enabled": True,
            "error": "hosted completion produced no url",
            "captcha": str(captured.get("hosted_captcha") or ""),
        }
    log(f"托管链补单成功：{result_url[:180]}")
    return {
        "enabled": True,
        "url": result_url,
        "qr_urls": list(captured.get("qr_urls") or []),
        "billing": json.dumps(
            {
                "method_selector": captured.get("method_selector"),
                "submit_selector": captured.get("submit_selector"),
                "billing_before_submit": captured.get("billing_before_submit"),
            },
            ensure_ascii=False,
        )[:400],
        "confirm_submitted": bool(captured.get("hosted_confirm_submitted")),
        "confirm_state": str(captured.get("hosted_confirm_state") or ""),
        "confirm_attempt_id": str(captured.get("hosted_confirm_attempt_id") or ""),
        "approve_submitted": bool(captured.get("hosted_approve_submitted")),
        "approve_proxy": str(captured.get("hosted_approve_proxy") or ""),
        "approve_error": str(captured.get("hosted_approve_error") or "")[:200],
    }


def hosted_manual_fallback_url(checkout: dict[str, Any], hosted_url: str = "") -> str:
    """Return the hosted checkout URL used when the 0 元 chain cannot be auto-completed.

    0 元场景里 approve 通过后 OpenAI/Stripe 仍可能只回
    ``checkout_approval_internal_error``；此时把官方托管结账页交给人工完成，
    比直接判失败更有价值（对齐同类平台的交付方式）。
    """
    url = str(hosted_url or "").strip()
    if url.startswith(("http://", "https://")):
        return url
    cs_id = str(checkout.get("cs_id") or "").strip()
    if cs_id:
        return f"https://pay.openai.com/c/pay/{cs_id}"
    return ""


def hosted_checkout_url_source(checkout: dict[str, Any], hosted_url: str = "") -> str:
    """判定交付的托管链接来源，方便日志/统计区分「带 #fid 签名」的原始链接。

    - ``stripe_init``：Stripe init 返回的 ``checkout.stripe.com/c/pay/cs_live_…#fid…``
      （带签名，可直接在真浏览器打开点订阅）。
    - ``pay_openai``：OpenAI 域名托管页（``pay.openai.com``）。
    - ``openai_pay_long_url``：无 ``stripe_hosted_url`` 时按 cs_id 拼接的跳转式链接
      （无 #fid 签名）。
    """
    url = str(hosted_url or "").strip()
    if url.startswith(("http://", "https://")):
        host = (urlsplit(url).netloc or "").lower()
        if host == "checkout.stripe.com":
            return "stripe_init"
        if host == "pay.openai.com":
            return "pay_openai"
        return "hosted"
    if str(checkout.get("cs_id") or "").strip():
        return "openai_pay_long_url"
    return ""


def run_provider_flow(
    access_token: str,
    session_token: str,
    checkout_proxy: str,
    promotion_proxy: str,
    provider_proxy: str,
    approve_pool: list[str],
    device_id: str,
    checkout: dict[str, str],
    billing: dict[str, str],
    stop_event: Event | None = None,
    fingerprint_profile: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    checkout_country = normalize_country(os.environ.get("UPI_CHECKOUT_COUNTRY", UPI_BOOTSTRAP_COUNTRY))
    stripe_pk = checkout.get("stripe_pk") or DEFAULT_STRIPE_PK
    fingerprint = dict(fingerprint_profile or {})
    require_zero = env_bool("UPI_REQUIRE_ZERO", True)
    checkout_provider = str(checkout.get("checkout_provider") or "").strip().lower()
    oaics_id = str(checkout.get("cs_id") or "").startswith("oaics_")
    browser_paths = {
        "官方Checkout兜底": env_bool("UPI_OFFICIAL_CHECKOUT_FALLBACK", True),
        "托管链优先": env_bool("UPI_HOSTED_FIRST", False),
        "托管链闭环补单": env_bool("UPI_HOSTED_COMPLETE", False),
    }
    if not any(browser_paths.values()):
        log(
            "纯协议模式：官方 Checkout 兜底 / 托管链优先 / 托管链闭环均关闭，"
            "本轮全程使用 curl-cffi 指纹 HTTP，不会启动无头浏览器"
        )
    if checkout_provider == "open_ai" or oaics_id:
        log("检测到 OpenAI OAICS 自定义 Checkout，切换 OAICS/UPI 链路（Elements + ConfirmationToken）")
        try:
            return run_oaics_upi_flow(
                access_token,
                session_token,
                checkout_proxy,
                provider_proxy,
                device_id,
                checkout,
                billing,
                stop_event,
                fingerprint,
                require_zero,
                checkout_country,
            )
        except Exception as oaics_error:  # noqa: BLE001
            hosted_fallback = (
                hosted_manual_fallback_url(checkout)
                # 托管链兜底是管理员开关（默认关闭），关闭时不再交付人工托管链接。
                if env_bool("UPI_HOSTED_FALLBACK", False)
                and require_zero
                and str(_oaics_due_amount(checkout)) == "0"
                else ""
            )
            if not hosted_fallback:
                if env_bool("UPI_HOSTED_FALLBACK", False) is False:
                    log(
                        "托管链兜底已关闭（管理员开关）：OAICS 0 元链未产出 instructions "
                        f"时不交付官方托管结账链接；原因={str(oaics_error)[:180]}",
                        "[WARN] ",
                    )
                raise
            log(
                "OAICS 0 元链路未能产出 UPI instructions"
                f"（{str(oaics_error)[:120]}），兜底交付官方托管结账链接（需人工完成）："
                f"{hosted_fallback[:160]}",
                "[WARN] ",
            )
            log(
                "UPI_RESULT_META:"
                + json.dumps(
                    {
                        "payment_method": "upi",
                        "checkout_kind": "oaics",
                        "amount": 0,
                        "zero": True,
                        "upi_instructions_url": "",
                        "hosted_checkout_url": hosted_fallback,
                        "hosted_checkout_url_source": hosted_checkout_url_source(checkout),
                        "manual_completion": True,
                        "manual_completion_reason": str(oaics_error)[:180],
                        "fingerprint_id": _fingerprint_value(fingerprint, "fingerprint_id"),
                        "fingerprint_mode": _fingerprint_value(fingerprint, "mode", default="sticky"),
                        "device_id_suffix": str(device_id or "")[-8:],
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            return hosted_fallback, []

    def inspect_init(payload: dict[str, Any], stage: str) -> tuple[dict[str, Any], int]:
        current_ctx = build_ctx(payload, checkout)
        current_amount = int(current_ctx["checkout_amount"])
        methods = list(current_ctx["payment_methods"])
        amount_major = current_amount / 100
        log(
            f"{stage} Stripe init 成功, 金额={checkout['currency']} {amount_major:.2f} "
            f"(source={current_ctx['checkout_amount_source']})"
        )
        log(f"{stage} Stripe 可用支付方式: {methods}")
        return current_ctx, current_amount

    log(
        f"{UPI_BOOTSTRAP_COUNTRY} Bootstrap Stripe init "
        f"(PM={billing['country']}, proxy={proxy_label(checkout_proxy)})..."
    )
    init_payload = stripe_init(
        checkout["cs_id"],
        stripe_pk,
        checkout_proxy,
        fingerprint_profile=fingerprint,
        device_id=device_id,
    )
    if not checkout.get("processor_entity"):
        processor_entity = infer_processor_entity(init_payload)
        if processor_entity:
            checkout["processor_entity"] = processor_entity
            log(f"从 Stripe init 推断 processor_entity={processor_entity}")
    bootstrap_ctx, bootstrap_amount = inspect_init(
        init_payload, f"{UPI_BOOTSTRAP_COUNTRY} Bootstrap"
    )
    # 原价链快速失败：Bootstrap 阶段金额已是 0，说明上游按账号资格把金额判成 0，
    # 后续 tax / PM / confirm / approve 都不会改变这个事实。直接判失败（账号级），
    # 省掉一整轮代理消耗和 20-30 秒耗时。开启 UPI_ORIGINAL_PRICE_ZERO_FALLBACK
    # 时跳过此快检，改为按 0 元链继续交付。
    if (
        not require_zero
        and int(bootstrap_amount or 0) == 0
        and not original_price_zero_fallback_enabled()
    ):
        raise RuntimeError(
            f"{UPI_ORIGINAL_PRICE_APPROVAL_REQUIRED}: 原价链被上游压成 0 元"
            "（Bootstrap 阶段金额即为 0）：OpenAI 按该账号的 0 元试用/满减资格"
            "自动把 checkout 金额判为 0（实测 mode=off 建单金额仍为 0，"
            "与链路是否注入优惠无关）。该账号无法产出正价 UPI 链；"
            "请更换无试用/折扣资格的账号走原价链，或改用 0 元链。"
            f"（checkout={checkout.get('cs_id', '')[:24]}，amount=0）"
        )
    if stop_event and stop_event.is_set():
        raise RuntimeError("任务已停止，跳过本轮")

    hosted_url = str(init_payload.get("stripe_hosted_url") or "")
    ctx: dict[str, Any] = dict(bootstrap_ctx)
    amount = bootstrap_amount
    promotion_payload: dict[str, Any] = {}
    tax_payload: dict[str, Any] = {}
    # 用户选择「原价链」时跳过优惠 checkout/update：这一步会把 campaign 折扣
    # 打上（很多 dr/post 号会自动命中 0 元试用），金额被压到 0 后又回到
    # 人工审批的 0 元链路。跳过它才能稳定拿到正价 UPI mandate。
    skip_promotion = (not require_zero) and env_bool("UPI_ORIGINAL_PRICE_SKIP_PROMO", True)
    if skip_promotion:
        log("提链类型=原价链：跳过优惠 checkout/update，保留原价金额")
    promotion_countries = () if skip_promotion else UPI_PROMOTION_COUNTRIES
    for promotion_index, promotion_country in enumerate(promotion_countries, start=1):
        current_promotion_proxy = proxy_for_country(promotion_proxy, promotion_country)
        stage_label = f"{promotion_country} checkout/update {promotion_index}/{len(UPI_PROMOTION_COUNTRIES)}"
        log(f"{stage_label}: proxy={proxy_label(current_promotion_proxy)}")
        try:
            promotion_chatgpt = build_chatgpt_session(
                access_token,
                device_id,
                current_promotion_proxy,
                session_token,
                fingerprint_profile=fingerprint,
            )
            promotion_payload = update_checkout_promotion(
                promotion_chatgpt,
                checkout,
                promotion_country,
                billing=billing,
            )
        except Exception as exc:
            if is_checkout_not_active_error(exc):
                raise
            raise RuntimeError(f"promotion 阶段失败: {exc}") from exc
        record_proxy_result("promotion", current_promotion_proxy, True, "promotion_update_success")

        log(
            f"{stage_label} 后通过 {UPI_PROVIDER_COUNTRY} 刷新 Stripe: "
            f"proxy={proxy_label(provider_proxy)}"
        )
        init_payload = stripe_init(
            checkout["cs_id"],
            stripe_pk,
            provider_proxy,
            fingerprint_profile=fingerprint,
            device_id=device_id,
        )
        hosted_url = str(init_payload.get("stripe_hosted_url") or hosted_url or "")
        ctx, amount = inspect_init(
            init_payload, f"{promotion_country} 更新后 {UPI_PROVIDER_COUNTRY}"
        )
        record_checkout_zero_result(checkout_proxy, checkout_country, amount)
        if amount == 0:
            log("Promotion 后金额为 0，继续按 0 元 UPI 流程提取最终支付 URL")
            break
        if not require_zero:
            log(
                f"UPI_REQUIRE_ZERO=0：Promotion 后金额仍为 {amount}，"
                "继续尝试提取原价 UPI 链。",
                "[WARN] ",
            )
            break
        if promotion_index < len(UPI_PROMOTION_COUNTRIES):
            log(
                f"{promotion_country} 更新后金额仍非 0，继续下一段 checkout/update",
                "[WARN] ",
            )
            continue
        raise RuntimeError(
            f"{UPI_AMOUNT_NONZERO_ERROR}: 0 元优惠未生效，当前金额小单位={amount}"
        )

    stripe = new_session(provider_proxy, fingerprint_profile=fingerprint)
    stripe.headers.update(
        {
            "User-Agent": _fingerprint_value(
                fingerprint,
                "ua",
                "user_agent",
                default=random_user_agent(),
            ),
            "Accept-Language": _fingerprint_value(
                fingerprint,
                "accept_language",
                "locale",
                default=payment_accept_language(),
            ),
        }
    )
    configure_stripe_fetch_origin(stripe)

    official_capture: dict[str, Any] = {}
    # 0 元链兜底状态：approve 已通过但拿不到 instructions 时交付官方托管结账链接。
    manual_state: dict[str, Any] = {"url": "", "reason": "", "completed": ""}

    def approve_hosted_confirm(_confirm_payload: dict[str, Any]) -> dict[str, Any]:
        """托管页 Confirm 进入 requires_approval 后，用同一账号上下文完成 approve。"""
        approve_proxies = approve_proxy_candidates(
            checkout_proxy,
            provider_proxy,
            approve_pool,
        )
        selected_proxy = approve_with_retry(
            access_token,
            device_id,
            checkout,
            approve_proxies,
            session_token,
            "provider",
            fingerprint,
        )
        return {"approved": True, "approve_proxy": selected_proxy}

    def manual_hosted_fallback(reason: Any) -> str:
        """0 元场景下把官方托管结账链接作为最终交付（需人工完成最后一步）。"""
        if manual_state["url"]:
            return manual_state["url"]
        if not require_zero or int(ctx.get("checkout_amount") or 0) != 0:
            return ""
        url = hosted_manual_fallback_url(checkout, hosted_url)
        if not url:
            return ""
        source = hosted_checkout_url_source(checkout, hosted_url)
        manual_state["source"] = source

        # 托管链补单模式（半自动）：先用无头指纹浏览器打开托管结账页，
        # 自动补账单/选 UPI/点订阅；Confirm 进入 requires_approval 后立即
        # 使用同一账号上下文完成 OpenAI approve，再等待页面 poll 出 instructions/QR。
        completed = complete_hosted_checkout_in_browser(
            stripe,
            checkout,
            url,
            device_id=device_id,
            session_token=session_token,
            billing=billing,
            fingerprint_profile=fingerprint,
            reason=reason,
            approval_callback=approve_hosted_confirm,
        )
        manual_state["confirm_submitted"] = bool(completed.get("confirm_submitted"))
        manual_state["confirm_state"] = str(completed.get("confirm_state") or "")
        manual_state["confirm_attempt_id"] = str(completed.get("confirm_attempt_id") or "")
        manual_state["approve_submitted"] = bool(completed.get("approve_submitted"))
        manual_state["approve_error"] = str(completed.get("approve_error") or "")[:200]
        manual_state["approve_proxy"] = str(completed.get("approve_proxy") or "")
        if completed.get("captcha"):
            # 托管页命中人机验证说明这个出口已被标记：记失败分，下次提链优先换出口。
            manual_state["captcha"] = str(completed["captcha"])[:40]
            for group, value in (("provider", provider_proxy), ("seed", checkout_proxy)):
                if value:
                    record_proxy_result(group, value, False, "hosted_captcha")
            log(
                f"托管页命中人机验证（{manual_state['captcha']}）：本出口已按失败计入代理评分，"
                "下一次提链会优先换出口；若持续命中需要更换更干净的 IN 住宅/移动出口。",
                "[WARN] ",
            )
        if completed.get("url"):
            manual_state["url"] = str(completed["url"])
            manual_state["reason"] = ""
            manual_state["completed"] = "1"
            manual_state["qr_urls"] = list(completed.get("qr_urls") or [])
            manual_state["billing"] = str(completed.get("billing") or "")
            return manual_state["url"]

        # 补单没跑通：托管链兜底是管理员开关，默认关闭。关闭时不交付人工托管链接，
        # 直接保留上游真实错误（approve blocked / poll timeout 等）。
        if not env_bool("UPI_HOSTED_FALLBACK", False):
            if not manual_state.get("hosted_fallback_disabled_logged"):
                manual_state["hosted_fallback_disabled_logged"] = "1"
                log(
                    "托管链兜底已关闭（管理员开关）：不交付官方托管结账链接，"
                    f"按上游错误结束本轮；原因={str(reason or '-')[:180]}",
                    "[WARN] ",
                )
            return ""

        manual_state["url"] = url
        manual_state["reason"] = str(reason or "checkout_approval_internal_error")[:180]
        manual_state["billing"] = str(completed.get("billing") or "")
        # 只有真的开启了托管链补单、且补单失败时才记录补单错误；
        # 开关关闭时保留上游失败原因（checkout_approval_internal_error 等）。
        manual_state["complete_error"] = (
            str(completed.get("error") or "")[:180] if completed.get("enabled") else ""
        )
        log(
            "0 元链审批后未拿到 UPI instructions，兜底交付官方托管结账链接"
            f"（需人工完成，来源={source}）：{url[:160]}",
            "[WARN] ",
        )
        return url

    def has_upi_instructions(redirect: str, candidates: list[str]) -> bool:
        return any(
            is_upi_instructions_url(item)
            for item in [redirect, *candidates]
            if str(item or "").strip()
        )

    def use_official_checkout_fallback(
        redirect: str,
        candidates: list[str],
        primary_error: Exception | None = None,
    ) -> tuple[str, list[str]]:
        nonlocal official_capture
        if has_upi_instructions(redirect, candidates):
            return redirect, candidates
        if not env_bool("UPI_OFFICIAL_CHECKOUT_FALLBACK", True):
            manual_url = manual_hosted_fallback(primary_error)
            if manual_url:
                return manual_url, []
            if primary_error is not None:
                raise primary_error
            return redirect, candidates

        log(
            "API confirm 未拿到 payments.stripe.com/upi/instructions，"
            "切换官方 Checkout 页面捕获 UPI QR/Instructions...",
            "[WARN] ",
        )
        try:
            captured = capture_upi_qr_from_checkout_page(
                stripe,
                checkout,
                device_id=device_id,
                session_token=session_token,
                billing=billing,
                fingerprint_profile=fingerprint,
            )
        except Exception as fallback_exc:
            fallback_detail = str(fallback_exc)[:700]
            manual_url = manual_hosted_fallback(primary_error or fallback_exc)
            if manual_url:
                return manual_url, []
            if primary_error is not None:
                raise RuntimeError(
                    f"{str(primary_error)[:700]}；"
                    f"{UPI_OFFICIAL_CHECKOUT_CAPTURE_FAILED}: {fallback_detail}"
                ) from fallback_exc
            log(
                f"官方 Checkout fallback 未成功，保留 API 结果：{fallback_detail}",
                "[WARN] ",
            )
            return redirect, candidates

        official_capture = dict(captured)
        captured_candidates = [
            str(captured.get("upi_instructions_url") or "").strip(),
            *[
                str(item or "").strip()
                for item in captured.get("qr_urls", [])
                if str(item or "").strip()
            ],
        ]
        merged_candidates = list(dict.fromkeys([*candidates, *captured_candidates]))
        fallback_url = str(captured.get("result_url") or "").strip()
        fallback_url = preferred_upi_result_url(fallback_url, merged_candidates)
        if not fallback_url:
            error = RuntimeError(
                f"{UPI_OFFICIAL_CHECKOUT_QR_NOT_FOUND}: 官方 Checkout 未返回可用结果"
            )
            manual_url = manual_hosted_fallback(primary_error or error)
            if manual_url:
                return manual_url, []
            if primary_error is not None:
                raise RuntimeError(
                    f"{str(primary_error)[:700]}；{error}"
                ) from error
            log(str(error), "[WARN] ")
            return redirect, candidates
        log(f"官方 Checkout 捕获到 UPI 结果: {fallback_url[:180]}")
        return fallback_url, merged_candidates

    if env_bool("UPI_UPDATE_TAX_REGION", False):
        log(f"同步 {UPI_PROVIDER_COUNTRY} checkout/taxes 与 Stripe tax_region...")
        tax_chatgpt = build_chatgpt_session(
            access_token,
            device_id,
            provider_proxy,
            session_token,
            fingerprint_profile=fingerprint,
        )
        tax_payload = update_upi_checkout_taxes(tax_chatgpt, checkout, billing)
        stripe_update_tax_region(stripe, checkout["cs_id"], stripe_pk, ctx, billing)
        init_payload = stripe_init(
            checkout["cs_id"],
            stripe_pk,
            provider_proxy,
            fingerprint_profile=fingerprint,
            device_id=device_id,
        )
        hosted_url = str(init_payload.get("stripe_hosted_url") or hosted_url or "")
        ctx, amount = inspect_init(init_payload, f"{UPI_PROVIDER_COUNTRY} 税务同步")
        record_checkout_zero_result(checkout_proxy, checkout_country, amount)
        if amount != 0 and require_zero:
            raise RuntimeError(
                f"{UPI_AMOUNT_NONZERO_ERROR}: 税务同步后当前金额小单位={amount}"
            )
        if amount != 0:
            log(
                f"UPI_REQUIRE_ZERO=0：税务同步后金额仍为 {amount}，"
                "继续尝试提取原价 UPI 链。",
                "[WARN] ",
            )

    # 托管链优先（管理员开关 UPI_HOSTED_FIRST，默认关闭）：先让 Stripe 托管页自己
    # 完成 Confirm → approve → poll，再回落 API confirm 链路。
    #
    # 为什么必须「优先」：API confirm 一旦跑过（哪怕失败），同一个 Checkout 的托管页
    # 会直接停在 Processing / "Please try again."，不再渲染支付方式选择，托管页也就
    # 无法再触发自己的 confirm —— 这正是之前托管链被 hCaptcha/失败态拦住的结构性原因。
    if env_bool("UPI_HOSTED_FIRST", False) and hosted_url and require_zero:
        log(
            f"托管链优先：先用托管页走 Confirm → approve → poll（{hosted_url[:120]}）"
        )
        try:
            hosted_first = complete_hosted_checkout_in_browser(
                stripe,
                checkout,
                hosted_url,
                device_id=device_id,
                session_token=session_token,
                billing=billing,
                fingerprint_profile=fingerprint,
                reason="hosted-first",
                approval_callback=approve_hosted_confirm,
            )
        except Exception as exc:  # noqa: BLE001 - 失败要回落 API 链路
            hosted_first = {
                "enabled": True,
                "error": re.sub(r"\s+", " ", str(exc or "")).strip()[:300],
            }
        if hosted_first.get("captcha"):
            for group, value in (("provider", provider_proxy), ("seed", checkout_proxy)):
                if value:
                    record_proxy_result(group, value, False, "hosted_captcha")
            log(
                f"托管链优先命中人机验证（{hosted_first['captcha']}）：本出口已按失败计分",
                "[WARN] ",
            )
        hosted_first_url = str(hosted_first.get("url") or "").strip()
        if hosted_first_url:
            hosted_first_qr = list(hosted_first.get("qr_urls") or [])
            capture_meta = upi_capture_metadata([hosted_first_url, *hosted_first_qr])
            deep_link = hydrate_upi_deep_link(stripe, [hosted_first_url, *hosted_first_qr])
            if deep_link.get("qr_image_png") and not capture_meta.get("upi_qr_png"):
                capture_meta["upi_qr_png"] = str(deep_link["qr_image_png"])
            if deep_link.get("qr_image_svg") and not capture_meta.get("upi_qr_svg"):
                capture_meta["upi_qr_svg"] = str(deep_link["qr_image_svg"])
            hosted_approve_proxy = str(hosted_first.get("approve_proxy") or "")
            if hosted_approve_proxy:
                record_proxy_pair_approve_success(
                    checkout_proxy, provider_proxy, hosted_approve_proxy
                )
            log(f"托管链优先闭环成功：{hosted_first_url[:180]}")
            log(
                "UPI_RESULT_META:"
                + json.dumps(
                    {
                        "payment_method": "upi",
                        "checkout_kind": (
                            "oaics"
                            if str(checkout.get("cs_id") or "").startswith("oaics_")
                            else "cs_live"
                            if str(checkout.get("cs_id") or "").startswith("cs_")
                            else str(checkout.get("checkout_provider") or "unknown")
                        ),
                        "payment_methods": list(ctx.get("payment_methods") or []),
                        "upi_detected": "upi" in list(ctx.get("payment_methods") or []),
                        "amount": int(ctx.get("checkout_amount") or 0),
                        "amount_source": str(ctx.get("checkout_amount_source") or ""),
                        "zero": int(ctx.get("checkout_amount") or 0) == 0,
"link_type": "zero" if int(ctx.get("checkout_amount") or 0) == 0 else "original",
"original_price_zero_fallback": bool(
    not require_zero and int(ctx.get("checkout_amount") or 0) == 0
),
                        "promo_detected": False,
                        "trial_detected": False,
                        "fingerprint_id": _fingerprint_value(fingerprint, "fingerprint_id"),
                        "fingerprint_mode": _fingerprint_value(fingerprint, "mode", default="sticky"),
                        "device_id_suffix": str(device_id or "")[-8:],
                        "browser_transport": "playwright-headless-chromium",
                        "qr_urls": list(capture_meta.get("qr_urls") or hosted_first_qr),
                        "upi_qr_png": str(capture_meta.get("upi_qr_png") or ""),
                        "upi_qr_svg": str(capture_meta.get("upi_qr_svg") or ""),
                        "upi_instructions_url": str(capture_meta.get("upi_instructions_url") or ""),
                        "provider_redirect_url": str(capture_meta.get("upi_instructions_url") or ""),
                        "upi_uri": str(deep_link.get("upi_uri") or ""),
                        "upi_expires_at": int(deep_link.get("expires_at") or 0),
                        "upi_deep_link_ready": bool(deep_link.get("upi_uri")),
                        "upi_intent_state": str(
                            deep_link.get("intent_state") or capture_meta.get("intent_state") or ""
                        ),
                        "upi_setup_intent_id": str(
                            deep_link.get("setup_intent_id")
                            or capture_meta.get("setup_intent_id")
                            or ""
                        ),
                        "official_checkout_capture": True,
                        "manual_completion": False,
                        "manual_completion_reason": "",
                        "hosted_checkout_url": "",
                        "hosted_complete": True,
                        "hosted_checkout_url_source": "",
                        "hosted_confirm_submitted": bool(
                            hosted_first.get("confirm_submitted")
                        ),
                        "hosted_confirm_state": str(hosted_first.get("confirm_state") or ""),
                        "hosted_confirm_attempt_id": str(
                            hosted_first.get("confirm_attempt_id") or ""
                        ),
                        "hosted_approve_submitted": bool(hosted_first.get("approve_submitted")),
                        "hosted_approve_error": str(hosted_first.get("approve_error") or "")[:200],
                        "hosted_captcha": str(hosted_first.get("captcha") or ""),
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            return hosted_first_url, hosted_first_qr
        log(
            "托管链优先未拿到 instructions，回落 API confirm 链路："
            f"{str(hosted_first.get('error') or 'no url')[:200]}",
            "[WARN] ",
        )

    pm_id = ""
    if env_bool("UPI_CONFIRM_INLINE_PM", False):
        log(
            f"UPI confirm 内联资料: {billing['name']} / "
            f"{billing['line1']} / {billing['city']} {billing['postal_code']}"
        )
    else:
        log(f"创建 PM (UPI): {billing['country']} {billing['name']} / {billing['city']}")
        pm_id = stripe_create_upi_pm(stripe, checkout["cs_id"], stripe_pk, billing, ctx)
        log(f"PM 创建成功: {pm_id}")
        log(
            f"印度资料已填入 PM billing_details: {billing['name']} / "
            f"{billing['line1']} / {billing['city']} {billing['postal_code']}"
        )

    if env_bool("UPI_UPDATE_CUSTOMER_DATA", False):
        log(
            f"提交印度资料填充: {billing['name']} / {billing['line1']} / "
            f"{billing['city']} {billing['postal_code']} / {billing['email']}"
        )
        stripe_update_customer_data(stripe, checkout["cs_id"], stripe_pk, ctx, billing)

    if env_bool("UPI_CHECKOUT_SNAPSHOT", False):
        snapshot_chatgpt = build_chatgpt_session(
            access_token,
            device_id,
            provider_proxy,
            session_token,
            fingerprint_profile=fingerprint,
        )
        checkout_snapshot(snapshot_chatgpt, checkout, billing)

    log("Stripe confirm (expected=UPI)...")
    confirm_payload = stripe_confirm_upi(stripe, checkout["cs_id"], pm_id, stripe_pk, init_payload, ctx, checkout, hosted_url, billing)
    log("Stripe confirm 成功, 解析跳转...")
    log_payment_page_summary("confirm", confirm_payload)
    if stop_event and stop_event.is_set():
        raise RuntimeError("任务已停止，跳过本轮")

    approve_proxy = ""
    qr_urls: list[str] = []
    resolve_error: Exception | None = None
    try:
        redirect_url, qr_urls, approve_proxy = resolve_confirm_payload_upi(
            stripe,
            confirm_payload,
            checkout,
            stripe_pk,
            ctx,
            pm_id,
            access_token,
            device_id,
            session_token,
            checkout_proxy,
            provider_proxy,
            approve_pool,
            fingerprint,
        )
    except Exception as exc:
        resolve_error = exc
        if is_terminal_approval_error(exc):
            raise
        if not should_retry_second_confirm_after_approve(exc):
            redirect_url, qr_urls = use_official_checkout_fallback("", [], exc)
        else:
            log(f"approve/confirm 后未拿到 redirect，刷新 Stripe init 后二次 confirm: {str(exc)[:180]}", "[WARN] ")
            try:
                init_payload = stripe_init(
                    checkout["cs_id"],
                    stripe_pk,
                    provider_proxy,
                    fingerprint_profile=fingerprint,
                    device_id=device_id,
                )
                hosted_url = str(init_payload.get("stripe_hosted_url") or hosted_url or "")
                ctx, amount = inspect_init(init_payload, f"{UPI_PROVIDER_COUNTRY} 二次 confirm 刷新")
                if amount != 0 and require_zero:
                    raise RuntimeError(
                        f"{UPI_AMOUNT_NONZERO_ERROR}: 二次 confirm 刷新金额小单位={amount}"
                    )
                if amount != 0:
                    log(
                        f"UPI_REQUIRE_ZERO=0：二次 confirm 刷新金额仍为 {amount}，"
                        "继续尝试提取原价 UPI 链。",
                        "[WARN] ",
                    )
                confirm_payload = stripe_confirm_upi(stripe, checkout["cs_id"], pm_id, stripe_pk, init_payload, ctx, checkout, hosted_url, billing)
                log("二次 Stripe confirm 成功, 解析跳转...")
                log_payment_page_summary("second_confirm", confirm_payload)
                redirect_url, qr_urls, retry_approve_proxy = resolve_confirm_payload_upi(
                    stripe,
                    confirm_payload,
                    checkout,
                    stripe_pk,
                    ctx,
                    pm_id,
                    access_token,
                    device_id,
                    session_token,
                    checkout_proxy,
                    provider_proxy,
                    approve_pool,
                    fingerprint,
                )
                approve_proxy = retry_approve_proxy or approve_proxy
                resolve_error = None
            except Exception as retry_exc:
                resolve_error = retry_exc
                redirect_url, qr_urls = use_official_checkout_fallback("", [], retry_exc)

    if resolve_error is None and not has_upi_instructions(redirect_url, qr_urls):
        redirect_url, qr_urls = use_official_checkout_fallback(redirect_url, qr_urls)

    if redirect_url and approve_proxy:
        record_proxy_pair_approve_success(checkout_proxy, provider_proxy, approve_proxy)
        log("完成 - 已记忆此 checkout/provider/approve combo")

    # 0 元链兜底：approve 已通过但上游落在 checkout_approval_internal_error，
    # 拿不到 payments.stripe.com/upi/instructions 时，交付官方托管结账链接，
    # 由人工（客服/用户）在官方页面完成最后一步审批与支付。
    if not redirect_url and not qr_urls and require_zero and int(ctx.get("checkout_amount") or 0) == 0:
        if not manual_hosted_fallback(resolve_error) and resolve_error is not None:
            # 托管链兜底关闭时不交付人工链接；直接抛出上游真实原因
            # （approve blocked / checkout_approval_internal_error / poll 超时），
            # 避免任务只剩「未解析到结果链接」这种没有信息量的报错。
            raise resolve_error
    # 托管链补单成功（浏览器里点通了）→ 按正常结果交付，不算「需人工完成」。
    hosted_complete = manual_state.get("completed") == "1"
    if hosted_complete:
        redirect_url = str(manual_state.get("url") or "")
        qr_urls = list(manual_state.get("qr_urls") or [])
        approve_proxy = str(manual_state.get("approve_proxy") or approve_proxy)
        if approve_proxy:
            record_proxy_pair_approve_success(checkout_proxy, provider_proxy, approve_proxy)
            log("托管链闭环完成 - 已记忆此 checkout/provider/approve combo")
    manual_completion = bool(manual_state["url"]) and not hosted_complete
    manual_completion_reason = (
        str(manual_state.get("complete_error") or manual_state["reason"]) if manual_completion else ""
    )
    hosted_fallback_url = manual_state["url"] if manual_completion else ""
    if manual_completion:
        redirect_url = hosted_fallback_url
        qr_urls = []

    redirect_url = preferred_upi_result_url(redirect_url, qr_urls)
    if redirect_url and not manual_completion:
        final_url = resolve_external_redirect(stripe, redirect_url)
        if final_url and final_url != redirect_url:
            log(f"跟随 redirect 得到最终链: {final_url[:180]}")
            redirect_url = final_url

    capture_meta = upi_capture_metadata([redirect_url, *qr_urls])
    deep_link = hydrate_upi_deep_link(stripe, [redirect_url, *qr_urls])
    if deep_link.get("qr_image_png") and not capture_meta.get("upi_qr_png"):
        capture_meta["upi_qr_png"] = str(deep_link["qr_image_png"])
    if deep_link.get("qr_image_svg") and not capture_meta.get("upi_qr_svg"):
        capture_meta["upi_qr_svg"] = str(deep_link["qr_image_svg"])
    transport_name = getattr(stripe, "transport_name", "")
    if not isinstance(transport_name, str) or not transport_name:
        transport_name = "playwright-headless-chromium"
    metadata = {
        "payment_method": "upi",
        "checkout_kind": (
            "oaics"
            if str(checkout.get("cs_id") or "").startswith("oaics_")
            else "cs_live"
            if str(checkout.get("cs_id") or "").startswith("cs_")
            else str(checkout.get("checkout_provider") or "unknown")
        ),
        "payment_methods": list(ctx.get("payment_methods") or []),
        "upi_detected": "upi" in list(ctx.get("payment_methods") or []),
        "amount": int(ctx.get("checkout_amount") or 0),
        "amount_source": str(ctx.get("checkout_amount_source") or ""),
        "zero": int(ctx.get("checkout_amount") or 0) == 0,
"link_type": "zero" if int(ctx.get("checkout_amount") or 0) == 0 else "original",
"original_price_zero_fallback": bool(
    not require_zero and int(ctx.get("checkout_amount") or 0) == 0
),
        "promo_detected": bool(
            checkout.get("promo_detected") == "1"
            or payment_evidence(promotion_payload).get("promo_detected")
            or payment_evidence(tax_payload).get("promo_detected")
        ),
        "trial_detected": bool(
            checkout.get("trial_detected") == "1"
            or payment_evidence(promotion_payload).get("trial_detected")
            or payment_evidence(tax_payload).get("trial_detected")
        ),
        "fingerprint_id": _fingerprint_value(fingerprint, "fingerprint_id"),
        "fingerprint_mode": _fingerprint_value(fingerprint, "mode", default="sticky"),
        "device_id_suffix": str(device_id or "")[-8:],
        "browser_transport": transport_name,
        "qr_urls": list(capture_meta.get("qr_urls") or []),
        "upi_qr_png": str(capture_meta.get("upi_qr_png") or ""),
        "upi_qr_svg": str(capture_meta.get("upi_qr_svg") or ""),
        "upi_instructions_url": str(capture_meta.get("upi_instructions_url") or ""),
        # Stripe 侧真正的 UPI 跳转链；托管兜底时为空，避免被当成可扫码的 provider 链。
        "provider_redirect_url": str(capture_meta.get("upi_instructions_url") or ""),
        "upi_uri": str(deep_link.get("upi_uri") or ""),
        "upi_expires_at": int(deep_link.get("expires_at") or 0),
        "upi_deep_link_ready": bool(deep_link.get("upi_uri")),
        # UPI instructions 链是一次性支付动作：Stripe 在用户未于窗口内完成授权时
        # 会把 SetupIntent 判 abandoned → canceled，链接仍返回 HTTP 200 但无法付款。
        # 把状态一起交付，前端据此显示倒计时/失效提示。
        "upi_intent_state": str(
            deep_link.get("intent_state") or capture_meta.get("intent_state") or ""
        ),
        "upi_setup_intent_id": str(
            deep_link.get("setup_intent_id") or capture_meta.get("setup_intent_id") or ""
        ),
        "official_checkout_capture": bool(official_capture.get("official_checkout_capture")),
    }
    metadata["manual_completion"] = manual_completion
    metadata["manual_completion_reason"] = manual_completion_reason
    # 支付页面（托管结账链）与支付入口（instructions 0 元链）是两个独立资产，
    # 需要同时交付：入口用于扫码/深链付款，页面用于人工复核与兜底。
    # 过去只在「需人工完成」时才带 hosted_checkout_url，导致成功产出
    # instructions 的任务在界面上只剩一个空白的支付页面字段。
    metadata["hosted_checkout_url"] = hosted_fallback_url or (
        hosted_url if capture_meta.get("upi_instructions_url") else ""
    )
    metadata["hosted_complete"] = hosted_complete
    metadata["hosted_checkout_url_source"] = str(
        manual_state.get("source")
        or (
            hosted_checkout_url_source(checkout, hosted_url)
            if capture_meta.get("upi_instructions_url")
            else ""
        )
    )
    metadata["hosted_confirm_submitted"] = bool(manual_state.get("confirm_submitted"))
    metadata["hosted_confirm_state"] = str(manual_state.get("confirm_state") or "")
    metadata["hosted_confirm_attempt_id"] = str(manual_state.get("confirm_attempt_id") or "")
    metadata["hosted_approve_submitted"] = bool(manual_state.get("approve_submitted"))
    metadata["hosted_approve_error"] = str(manual_state.get("approve_error") or "")[:200]
    # 托管页人机验证（hCaptcha）：该出口已被风控标记，会同步到任务结果与统计里。
    metadata["hosted_captcha"] = str(manual_state.get("captcha") or "")[:40]
    if official_capture:
        metadata["official_checkout_capture_detail"] = {
            key: value
            for key, value in official_capture.items()
            if key
            in {
                "method_selector",
                "submit_selector",
                "billing_before_submit",
                "billing_after_submit",
                "page_url",
                "response_events",
            }
        }
    log("UPI_RESULT_META:" + json.dumps(metadata, ensure_ascii=False, separators=(",", ":")))
    return redirect_url, list(dict.fromkeys(qr_urls))


def resolve_attempt_upi_fingerprint(
    access_token: str,
    attempt: int,
    *,
    checkout_retry_index: int = 0,
) -> dict[str, str]:
    return _resolve_attempt_upi_fingerprint(
        access_token,
        attempt,
        checkout_retry_index=checkout_retry_index,
    )


def _resolve_attempt_upi_fingerprint(
    access_token: str,
    attempt: int,
    *,
    checkout_retry_index: int = 0,
) -> dict[str, str]:
    configured_mode = str(os.environ.get("UPI_FINGERPRINT_MODE", "sticky") or "sticky").strip().lower()
    if configured_mode not in {"sticky", "rotate"}:
        configured_mode = "sticky"
    rotate_on_retry = str(
        os.environ.get("UPI_ROTATE_FINGERPRINT_ON_RETRY", "1")
    ).strip().lower() not in {"0", "false", "no", "off"}
    force_rotate = configured_mode == "rotate" or (
        rotate_on_retry and (int(attempt or 1) > 1 or int(checkout_retry_index or 0) > 0)
    )
    mode = "rotate" if force_rotate else configured_mode
    profile = resolve_upi_fingerprint(
        access_token,
        account_id=os.environ.get("UPI_ACCOUNT_ID", ""),
        mode=mode,
        attempt=attempt,
        # A configured profile/device is the sticky baseline only. Reusing it
        # during a retry would keep the same browser identity after changing
        # the proxy, which is exactly the combination that repeatedly hit risk.
        profile={} if force_rotate else _load_upi_fingerprint_profile(),
        device_id="" if force_rotate else os.environ.get("UPI_DEVICE_ID", ""),
    )
    retry_label = ""
    if force_rotate:
        retry_label = (
            f"；重试已切换指纹会话(attempt={max(1, int(attempt or 1))}"
            f", checkout_retry={max(0, int(checkout_retry_index or 0))})"
        )
    log(
        f"UPI 浏览器指纹：{upi_fingerprint_label(profile, profile.get('device_id', ''))}"
        f"{retry_label}"
    )
    return profile


def _oaics_checkout_billing(checkout: dict[str, Any], fallback: dict[str, str]) -> dict[str, str]:
    """Use the billing the OAICS checkout already recorded; fallback to IN profile."""
    state = checkout.get("checkout_state") if isinstance(checkout.get("checkout_state"), dict) else {}
    billing_state = state.get("billingAddress") if isinstance(state.get("billingAddress"), dict) else {}
    address = billing_state.get("address") if isinstance(billing_state.get("address"), dict) else {}
    name = str(billing_state.get("name") or fallback.get("name") or "").strip()
    email = str(state.get("email") or fallback.get("email") or "").strip()
    country = str(address.get("country") or fallback.get("country") or "IN").strip().upper()
    result = {
        "name": name or "Tanvi Rao",
        "email": email or fallback.get("email") or "redacted@example.invalid",
        "line1": str(address.get("line1") or fallback.get("line1") or "24 Park Street").strip(),
        "line2": str(address.get("line2") or fallback.get("line2") or "").strip(),
        "city": str(address.get("city") or fallback.get("city") or "Mumbai").strip(),
        "state": str(address.get("state") or fallback.get("state") or "MH").strip(),
        "postal_code": str(address.get("postal_code") or fallback.get("postal_code") or "400001").strip(),
        "country": country,
    }
    if country == "IN":
        result.setdefault("currency", "INR")
    return result


def _oaics_mandate_amount_from_checkout(checkout: dict[str, Any]) -> int:
    """Mandate 授权上限：优先取 Checkout 里记录的原始正价金额。

    网页端的 UPI AutoPay 委托是「授权上限 + 按次扣款」，0 元首期只是本单
    免扣，授权上限仍是 Plus 正价。取不到正价时回落到配置默认值。
    """
    for key in ("original_checkout_amount", "checkout_amount", "amount"):
        value = checkout.get(key)
        try:
            amount = int(str(value))
        except (TypeError, ValueError):
            continue
        if amount > 0:
            return amount
    state = checkout.get("checkout_state") if isinstance(checkout.get("checkout_state"), dict) else {}
    for key in ("originalAmount", "amountTotal", "subtotal"):
        value = state.get(key)
        if isinstance(value, dict):
            value = value.get("minorUnitsAmount")
        try:
            amount = int(str(value))
        except (TypeError, ValueError):
            continue
        if amount > 0:
            return amount
    return 0


def _oaics_due_amount(checkout: dict[str, Any]) -> str:
    """Best-effort OAICS checkout due amount in minor units.

    新版 OpenAI 自定义 Checkout 的金额放在 checkout_state 的
    ``minorUnitsAmount`` 字段（subtotal/discount/total 均为对象），
    兼容 ``amount``/``due`` 等旧字段。
    """
    state = checkout.get("checkout_state") if isinstance(checkout.get("checkout_state"), dict) else {}

    def minor_of(value: Any, seen: set[int] | None = None) -> int | None:
        """Read the first numeric minor-unit amount in an OAICS amount object."""
        if seen is None:
            seen = set()
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
        if isinstance(value, str):
            text = value.strip().replace(",", "")
            if text and text.lstrip("-").isdigit():
                try:
                    return int(text)
                except (TypeError, ValueError):
                    return None
            return None
        if isinstance(value, dict):
            marker = id(value)
            if marker in seen:
                return None
            seen.add(marker)
            for key in ("minorUnitsAmount", "amount_due", "due", "amount_total", "amount"):
                found = minor_of(value.get(key), seen)
                if found is not None:
                    return found
            for key in ("total", "invoice", "totalSummary"):
                found = minor_of(value.get(key), seen)
                if found is not None:
                    return found
            return None
        if isinstance(value, list):
            total = 0
            found = False
            for item in value:
                minor = minor_of(item, seen)
                if minor is not None:
                    total += minor
                    found = True
            return total if found else None
        return None

    top_total = minor_of(state.get("total"))
    if top_total is not None:
        return str(top_total)
    line_items = state.get("lineItems")
    if isinstance(line_items, list):
        subtotal = 0
        discount = 0
        found_items = False
        for item in line_items:
            if not isinstance(item, dict):
                continue
            item_total = minor_of(item.get("total"))
            if item_total is not None:
                subtotal += item_total
                found_items = True
                continue
            item_subtotal = minor_of(item.get("subtotal"))
            if item_subtotal is None:
                continue
            subtotal += item_subtotal
            found_items = True
            entries = item.get("discountAmounts")
            if isinstance(entries, list) and entries:
                for entry in entries:
                    discount += minor_of(entry) or 0
            else:
                discount += minor_of(item.get("discount")) or 0
        if found_items:
            return str(max(0, subtotal - discount))
    invoice = state.get("invoice")
    if isinstance(invoice, dict):
        invoice_due = minor_of(invoice.get("amount_due"))
        if invoice_due is not None:
            return str(invoice_due)
    total_summary = state.get("totalSummary")
    if isinstance(total_summary, dict):
        summary_due = minor_of(total_summary.get("due"))
        if summary_due is not None:
            return str(summary_due)
    return "0"


def _oaics_elements_session(
    stripe: Any,
    *,
    stripe_pk: str,
    customer_session_client_secret: str,
    amount: str,
    stripe_js_id: str,
    elements_locale: str = "en",
    mandate_amount: int | None = None,
) -> dict[str, Any]:
    params = {
        "customer_session_client_secret": customer_session_client_secret,
        "client_betas[0]": "custom_checkout_server_updates_1",
        "client_betas[1]": "custom_checkout_manual_approval_1",
        "deferred_intent[mode]": "subscription",
        "deferred_intent[amount]": str(amount or "0"),
        "deferred_intent[currency]": "inr",
        "deferred_intent[setup_future_usage]": "off_session",
        "deferred_intent[payment_method_types][0]": "upi",
        "deferred_intent[payment_method_types][1]": "link",
        "currency": "inr",
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
        "elements_init_source": "stripe.elements",
        "referrer_host": "chatgpt.com",
        "stripe_js_id": stripe_js_id,
        "locale": str(elements_locale or "en"),
        "type": "deferred_intent",
    }
    if oaics_mandate_options_enabled():
        mandate_params = oaics_mandate_options_params(mandate_amount)
        params.update(mandate_params)
        log(
            "OAICS Elements 注入 UPI mandate_options："
            f"amount={mandate_params['deferred_intent[payment_method_options][upi][mandate_options][amount]']} "
            "amount_type=maximum"
        )
    try:
        resp = stripe.get("https://api.stripe.com/v1/elements/sessions", params=params, timeout=DEFAULT_TIMEOUT)
    except Exception as exc:
        raise RuntimeError(f"OAICS Stripe Elements 请求异常: {str(exc)[:200]}") from exc
    dump_http(resp, "oaics_elements", params, "GET", "https://api.stripe.com/v1/elements/sessions", force=resp.status_code >= 400)
    if resp.status_code >= 400:
        raise RuntimeError(f"OAICS Stripe Elements 失败 HTTP {resp.status_code}: {(resp.text or '')[:500]}")
    payload = resp.json() or {}
    if not isinstance(payload, dict):
        raise RuntimeError("OAICS Stripe Elements 响应不是对象")
    return payload


def _oaics_elements_ids(payload: dict[str, Any]) -> tuple[str, str]:
    session_id = str(
        payload.get("session_id")
        or payload.get("id")
        or payload.get("client_elements_session_id")
        or f"elements_session_{uuid.uuid4().hex[:11]}"
    )
    config_id = str(
        payload.get("config_id")
        or payload.get("elements_session_config_id")
        or payload.get("client_elements_session_config_id")
        or ""
    )
    return session_id, config_id


def _oaics_create_upi_pm(
    stripe: Any,
    *,
    stripe_pk: str,
    cs_id: str,
    billing: dict[str, str],
    stripe_js_id: str,
    elements_session_id: str,
    elements_config_id: str,
) -> str:
    body: dict[str, Any] = {
        "billing_details[name]": billing.get("name") or "Aisha Sharma",
        "billing_details[email]": billing.get("email") or "redacted@example.invalid",
        "billing_details[address][country]": billing.get("country") or "IN",
        "billing_details[address][line1]": billing.get("line1") or "24 Park Street",
        "billing_details[address][line2]": billing.get("line2") or "",
        "billing_details[address][city]": billing.get("city") or "Mumbai",
        "billing_details[address][postal_code]": billing.get("postal_code") or "400001",
        "type": "upi",
        "allow_redisplay": "limited",
        "payment_user_agent": (
            f"stripe.js/{DEFAULT_STRIPE_RUNTIME_VERSION}; "
            f"stripe-js-v3/{DEFAULT_STRIPE_RUNTIME_VERSION}; payment-element; deferred-intent"
        ),
        "referrer": "https://chatgpt.com",
        "time_on_page": str(random.randint(25000, 55000)),
        "client_attribution_metadata[checkout_session_id]": cs_id,
        "client_attribution_metadata[client_session_id]": stripe_js_id,
        "client_attribution_metadata[elements_session_id]": elements_session_id,
        "client_attribution_metadata[elements_session_config_id]": elements_config_id,
        "client_attribution_metadata[merchant_integration_source]": "elements",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[merchant_integration_version]": "2021",
        "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
    }
    if billing.get("state"):
        body["billing_details[address][state]"] = billing["state"]
    resp = stripe.post("https://api.stripe.com/v1/payment_methods", data=body, timeout=DEFAULT_TIMEOUT)
    dump_http(resp, "oaics_upi_pm", body, "POST", "https://api.stripe.com/v1/payment_methods", force=resp.status_code >= 400)
    if resp.status_code >= 400:
        raise RuntimeError(f"OAICS 创建 UPI PM 失败 HTTP {resp.status_code}: {(resp.text or '')[:500]}")
    pm_id = str((resp.json() or {}).get("id") or "")
    if not pm_id.startswith("pm_"):
        raise RuntimeError(f"OAICS 创建 UPI PM 响应异常: {(resp.text or '')[:300]}")
    return pm_id


def _oaics_create_confirmation_token(
    stripe: Any,
    *,
    stripe_pk: str,
    cs_id: str,
    pm_id: str,
    stripe_js_id: str,
    elements_session_id: str,
    elements_config_id: str,
    billing: dict[str, str] | None = None,
    inline: bool = False,
) -> str:
    if inline:
        billing = dict(billing or {})
        body: dict[str, Any] = {
            "payment_method_data[type]": "upi",
            "payment_method_data[billing_details][name]": str(billing.get("name") or ""),
            "payment_method_data[billing_details][address][line1]": str(billing.get("line1") or ""),
            "payment_method_data[billing_details][address][city]": str(billing.get("city") or ""),
            "payment_method_data[billing_details][address][country]": str(billing.get("country") or "IN"),
            "payment_method_data[billing_details][address][postal_code]": str(billing.get("postal_code") or ""),
            "payment_method_data[billing_details][address][state]": str(billing.get("state") or ""),
            "payment_method_data[payment_user_agent]": (
                "stripe.js/8444022167; stripe-js-v3/8444022167; payment-element; deferred-intent"
            ),
            "payment_method_data[referrer]": "https://chatgpt.com",
            "payment_method_data[time_on_page]": str(random.randint(30000, 90000)),
            "payment_method_data[client_attribution_metadata][client_session_id]": stripe_js_id,
            "payment_method_data[client_attribution_metadata][merchant_integration_source]": "elements",
            "payment_method_data[client_attribution_metadata][merchant_integration_subtype]": "payment-element",
            "payment_method_data[client_attribution_metadata][merchant_integration_version]": "2021",
            "payment_method_data[client_attribution_metadata][payment_intent_creation_flow]": "deferred",
            "payment_method_data[client_attribution_metadata][payment_method_selection_flow]": "merchant_specified",
            "payment_method_data[client_attribution_metadata][elements_session_id]": elements_session_id,
            "payment_method_data[client_attribution_metadata][elements_session_config_id]": elements_config_id,
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][0]": "expressCheckout",
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][1]": "payment",
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][2]": "address",
            "payment_method_data[guid]": stripe_browser_id(),
            "payment_method_data[muid]": stripe_browser_id(),
            "payment_method_data[sid]": stripe_browser_id(),
            "setup_future_usage": "off_session",
            "mandate_data[customer_acceptance][type]": "online",
            "mandate_data[customer_acceptance][online][infer_from_client]": "true",
            "client_context[currency]": "inr",
            "client_context[mode]": "subscription",
            "client_context[payment_method_types][0]": "link",
            "client_context[payment_method_types][1]": "card",
            "client_context[payment_method_types][2]": "upi",
            "client_attribution_metadata[checkout_session_id]": cs_id,
            "client_attribution_metadata[client_session_id]": stripe_js_id,
            "client_attribution_metadata[elements_session_id]": elements_session_id,
            "client_attribution_metadata[elements_session_config_id]": elements_config_id,
            "client_attribution_metadata[merchant_integration_source]": "elements",
            "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
            "client_attribution_metadata[merchant_integration_version]": "2021",
            "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
            "client_attribution_metadata[payment_method_selection_flow]": "merchant_specified",
            "client_attribution_metadata[merchant_integration_additional_elements][0]": "expressCheckout",
            "client_attribution_metadata[merchant_integration_additional_elements][1]": "payment",
            "client_attribution_metadata[merchant_integration_additional_elements][2]": "address",
            "set_as_default_payment_method": "false",
            "key": stripe_pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
        if not str(body["payment_method_data[billing_details][name]"] or "").strip():
            body["payment_method_data[billing_details][name]"] = "Aisha Sharma"
    else:
        body = {
            "payment_method": pm_id,
            "setup_future_usage": "off_session",
            "mandate_data[customer_acceptance][type]": "online",
            "mandate_data[customer_acceptance][online][infer_from_client]": "true",
            "client_context[currency]": "inr",
            "client_context[mode]": "subscription",
            "client_context[payment_method_types][0]": "upi",
            "client_attribution_metadata[checkout_session_id]": cs_id,
            "client_attribution_metadata[client_session_id]": stripe_js_id,
            "client_attribution_metadata[elements_session_id]": elements_session_id,
            "client_attribution_metadata[elements_session_config_id]": elements_config_id,
            "client_attribution_metadata[merchant_integration_source]": "elements",
            "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
            "client_attribution_metadata[merchant_integration_version]": "2021",
            "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
            "client_attribution_metadata[payment_method_selection_flow]": "automatic",
            "key": stripe_pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
    log(
        f"OAICS ConfirmationToken 构造：mode={'inline-payment-method-data' if inline else 'pm-reference'} "
        f"session={stripe_js_id[:8]}..."
    )
    resp = stripe.post("https://api.stripe.com/v1/confirmation_tokens", data=body, timeout=DEFAULT_TIMEOUT)
    dump_http(resp, "oaics_confirmation_token", body, "POST", "https://api.stripe.com/v1/confirmation_tokens", force=resp.status_code >= 400)
    if resp.status_code >= 400:
        raise RuntimeError(f"OAICS ConfirmationToken 失败 HTTP {resp.status_code}: {(resp.text or '')[:500]}")
    token = str((resp.json() or {}).get("id") or "")
    if not token.startswith(("ctoken_", "ct_")):
        raise RuntimeError(f"OAICS ConfirmationToken 响应缺少 token: {(resp.text or '')[:300]}")
    return token


def _oaics_chatgpt_confirm(
    chatgpt: Any,
    *,
    cs_id: str,
    processor_entity: str,
    confirmation_token: str,
) -> dict[str, Any]:
    checkout_page_url = f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}"
    route = "/backend-api/payments/checkout/confirm"
    headers = {
        "Referer": checkout_page_url,
        "x-openai-target-path": route,
        "x-openai-target-route": route,
        "Accept": "application/json",
        "OAI-Telemetry": "[1,null]",
    }
    ensure_upi_sentinel(
        chatgpt,
        flow="checkout_session_approval",
        page_url=checkout_page_url,
    )
    log("OAICS checkout/confirm 使用 OpenAI Sentinel 会话上下文")
    resp = chatgpt.post(
        f"https://chatgpt.com{route}",
        json={
            "checkout_session_id": cs_id,
            "confirm_token": confirmation_token,
            "selected_payment_method_type": "upi",
        },
        headers=headers,
        timeout=CHATGPT_TIMEOUT,
    )
    dump_http(resp, "oaics_chatgpt_confirm", None, "POST", f"https://chatgpt.com{route}", force=True)
    if resp.status_code >= 400:
        raise RuntimeError(f"OAICS checkout/confirm 失败 HTTP {resp.status_code}: {(resp.text or '')[:500]}")
    payload = resp.json() or {}
    if not isinstance(payload, dict):
        raise RuntimeError("OAICS checkout/confirm 响应不是对象")
    result = str(payload.get("result") or payload.get("status") or "").strip().lower()
    if result == "blocked":
        raise RuntimeError(
            "approve blocked: OAICS checkout/confirm 返回 blocked（OpenAI 0 元人工审批风控，"
            "官方 UI 同样提示 Payment was not approved）"
        )
    if result != "success":
        raise RuntimeError(f"OAICS checkout/confirm 未成功: status={result or '-'} {str(payload)[:400]}")
    return payload


def _oaics_upi_result(payload: Any) -> tuple[str, list[str]]:
    """Extract hosted UPI instructions URL / QR from a Stripe intent payload."""
    if isinstance(payload, dict):
        next_action = payload.get("next_action")
        if isinstance(next_action, dict):
            block = next_action.get("upi_handle_redirect_or_display_qr_code")
            if isinstance(block, dict):
                url = str(block.get("hosted_instructions_url") or "").strip()
                qr = block.get("qr_code")
                qr_urls = []
                if isinstance(qr, dict):
                    for key in ("image_url_png", "image_url_svg"):
                        value = str(qr.get(key) or "").strip()
                        if value:
                            qr_urls.append(value)
                if url and is_upi_instructions_url(url):
                    dead = dead_upi_intent_reason(payload)
                    if dead:
                        raise RuntimeError(
                            f"UPI intent 已被拒（废链，不交付）: {dead}"
                        )
                    return url, qr_urls
        for value in payload.values():
            url, qr_urls = _oaics_upi_result(value)
            if url:
                return url, qr_urls
    elif isinstance(payload, list):
        for value in payload:
            url, qr_urls = _oaics_upi_result(value)
            if url:
                return url, qr_urls
    return "", []


def _oaics_confirm_intent(
    stripe: Any,
    *,
    stripe_pk: str,
    confirm_payload: dict[str, Any],
    confirmation_token: str,
    stripe_js_id: str,
    cs_id: str = "",
    require_zero: bool = False,
    poll_seconds: int = 45,
) -> tuple[str, list[str]]:
    """Confirm the PaymentIntent/SetupIntent returned by OAICS checkout/confirm."""
    secret = str(confirm_payload.get("client_secret") or "").strip()
    intent_type = str(confirm_payload.get("type") or "").strip().lower()
    if "_secret_" not in secret:
        raise RuntimeError(f"OAICS checkout/confirm 未返回 client_secret: {str(confirm_payload)[:400]}")
    intent_id = secret.split("_secret_", 1)[0]
    return_url = str(
        confirm_payload.get("confirm_return_url")
        or ""
    ).strip()
    if not return_url:
        raise RuntimeError("OAICS checkout/confirm 未返回 confirm_return_url")
    body: dict[str, Any] = {
        "client_secret": secret,
        "confirmation_token": confirmation_token,
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
        "return_url": return_url,
        "client_attribution_metadata[client_session_id]": stripe_js_id,
        "client_attribution_metadata[merchant_integration_source]": "elements",
    }
    if intent_type == "payment_intent" and intent_id.startswith("pi_"):
        # 后台强制 0 元时，OAICS 正价 PaymentIntent 不得作为成功结果：
        # 先读取 Stripe PI 金额，非 0 直接按 UPI_AMOUNT_NONZERO 失败，由外层
        # 重试其它代理/Checkout 继续寻找 0 元优惠；避免把原价链误报为 0 元成功。
        if require_zero:
            read_amount = None
            read_error = ""
            try:
                read = stripe.get(
                    f"https://api.stripe.com/v1/payment_intents/{intent_id}",
                    params={"key": stripe_pk, "client_secret": secret},
                    timeout=DEFAULT_TIMEOUT,
                )
                if read.status_code < 400:
                    read_state = read.json() or {}
                    read_amount = read_state.get("amount")
                else:
                    read_error = f"HTTP {read.status_code}: {(read.text or '')[:200]}"
            except Exception as exc:
                read_error = str(exc)[:200]
            if read_amount is None:
                raise RuntimeError(
                    f"OAICS 0 元校验失败：无法读取 PaymentIntent 金额"
                    f"{('；' + read_error) if read_error else ''}"
                )
            try:
                amount_minor = int(read_amount)
            except (TypeError, ValueError):
                raise RuntimeError(f"OAICS 0 元校验失败：PaymentIntent amount 无效 {read_amount!r}")
            if amount_minor != 0:
                raise RuntimeError(
                    f"{UPI_AMOUNT_NONZERO_ERROR}: 后台强制 0 元，但 OAICS "
                    f"PaymentIntent 金额非 0（{amount_minor / 100:.2f} {str(confirm_payload.get('currency') or 'INR').upper()}，"
                    f"minor={amount_minor}，{intent_id[:20]}...）"
                )
            log("OAICS 0 元校验通过：PaymentIntent amount=0")
        endpoint = f"https://api.stripe.com/v1/payment_intents/{intent_id}/confirm"
    elif intent_type == "setup_intent" and intent_id.startswith("seti_"):
        endpoint = f"https://api.stripe.com/v1/setup_intents/{intent_id}/confirm"
    else:
        raise RuntimeError(
            f"OAICS 未知 intent 类型: type={intent_type or '-'} id={intent_id[:40]} {str(confirm_payload)[:400]}"
        )
    log(f"OAICS Stripe confirm: type={intent_type} id={intent_id[:32]}...")
    resp = stripe.post(endpoint, data=body, timeout=DEFAULT_TIMEOUT)
    dump_http(resp, "oaics_intent_confirm", body, "POST", endpoint, force=True)
    if resp.status_code >= 400:
        text = resp.text or ""
        if intent_type == "setup_intent" and resp.status_code == 402:
            if not chain_requires_zero() and not original_price_zero_fallback_enabled():
                # 原价链强制语义：SetupIntent(0 元) 被拒说明这个号只能走 0 元链路，
                # 直接判失败，不再重建 Checkout 绕圈。
                raise RuntimeError(
                    f"{UPI_ORIGINAL_PRICE_APPROVAL_REQUIRED}: 原价链命中 0 元 "
                    f"SetupIntent 被拒 HTTP 402：{text[:300]}；"
                    "该账号无法交付正价 UPI 链，请更换无自动试用/折扣的账号，或改用 0 元链。"
                )
            raise RuntimeError(
                f"approve blocked ({UPI_OAICS_ZERO_DECLINED}): "
                f"OAICS 0 元 UPI SetupIntent confirm 被拒 HTTP 402: {text[:500]}"
            )
        raise RuntimeError(f"OAICS {intent_type} confirm 失败 HTTP {resp.status_code}: {text[:500]}")
    payload = resp.json() or {}
    if not isinstance(payload, dict):
        raise RuntimeError("OAICS intent confirm 响应不是对象")
    url, qr_urls = _oaics_upi_result(payload)
    if url:
        next_action = payload.get("next_action") if isinstance(payload, dict) else None
        next_action = next_action if isinstance(next_action, dict) else {}
        expires_at = 0
        qr_block = None
        if isinstance(next_action.get("upi_handle_redirect_or_display_qr_code"), dict):
            qr_block = next_action["upi_handle_redirect_or_display_qr_code"].get("qr_code")
        if isinstance(qr_block, dict):
            try:
                expires_at = int(float(qr_block.get("expires_at") or 0))
            except (TypeError, ValueError):
                expires_at = 0
        capture_meta = upi_capture_metadata([url, *qr_urls])
        oaics_deep_link = hydrate_upi_deep_link(stripe, [url, *qr_urls])
        if oaics_deep_link.get("qr_image_png") and not capture_meta.get("upi_qr_png"):
            capture_meta["upi_qr_png"] = str(oaics_deep_link["qr_image_png"])
        if oaics_deep_link.get("qr_image_svg") and not capture_meta.get("upi_qr_svg"):
            capture_meta["upi_qr_svg"] = str(oaics_deep_link["qr_image_svg"])
        capture_meta.update(
            {
                "checkout_kind": (
                    "oaics"
                    if str(cs_id or "").startswith("oaics_")
                    else "cs_live"
                    if str(cs_id or "").startswith("cs_")
                    else "unknown"
                ),
                "upi_instructions_url": url,
                "provider_redirect_url": url,
                "upi_expires_at": expires_at,
                "next_action_type": str(next_action.get("type") or ""),
                "qr_urls": list(capture_meta.get("qr_urls") or qr_urls),
                "upi_qr_png": str(capture_meta.get("upi_qr_png") or ""),
                "upi_qr_svg": str(capture_meta.get("upi_qr_svg") or ""),
                "upi_uri": str(oaics_deep_link.get("upi_uri") or ""),
                "upi_deep_link_ready": bool(oaics_deep_link.get("upi_uri")),
                "deep_link_expires_at": int(oaics_deep_link.get("expires_at") or 0),
            }
        )
        log("UPI_RESULT_META:" + json.dumps(capture_meta, ensure_ascii=False, separators=(",", ":")))
        log(f"OAICS UPI 结果已返回: {url[:180]}")
        return url, qr_urls
    if intent_type != "payment_intent":
        return "", []
    deadline = time.time() + max(10, int(poll_seconds or 45))
    poll_url = f"https://api.stripe.com/v1/payment_intents/{intent_id}"
    while time.time() < deadline:
        time.sleep(1.2)
        try:
            poll = stripe.get(
                poll_url,
                params={"key": stripe_pk, "client_secret": secret},
                timeout=DEFAULT_TIMEOUT,
            )
        except Exception as exc:
            log(f"OAICS payment_intent 轮询异常: {str(exc)[:160]}", "[WARN] ")
            continue
        if poll.status_code >= 400:
            continue
        try:
            state = poll.json() or {}
        except Exception:
            state = {}
        url, qr_urls = _oaics_upi_result(state)
        if url:
            return url, qr_urls
        status = str(state.get("status") or "").strip()
        if status in {"succeeded", "processing"}:
            break
    return "", []


def run_oaics_upi_flow(
    access_token: str,
    session_token: str,
    checkout_proxy: str,
    provider_proxy: str,
    device_id: str,
    checkout: dict[str, Any],
    billing: dict[str, str],
    stop_event: Event | None,
    fingerprint: dict[str, Any],
    require_zero: bool,
    checkout_country: str,
) -> tuple[str, list[str]]:
    """OpenAI OAICS(open_ai/oaics_*) UPI compatibility chain.

    已实测打通：oaics checkout -> Elements -> UPI PM -> ConfirmationToken ->
    ChatGPT checkout/confirm(payment_intent) -> Stripe PI confirm ->
    payments.stripe.com/upi/instructions + QR。0 元试用分支仍受 OpenAI
    人工审批风控（checkout/confirm 直接 blocked 或 SetupIntent 402）。
    """
    if stop_event and stop_event.is_set():
        raise RuntimeError("任务已停止，跳过本轮")
    cs_id = str(checkout.get("cs_id") or "").strip()
    processor_entity = str(checkout.get("processor_entity") or "openai_llc").strip() or "openai_llc"
    stripe_pk = str(checkout.get("stripe_pk") or DEFAULT_STRIPE_PK).strip()
    customer_secret = str(checkout.get("customer_session_client_secret") or "").strip()
    proxy = provider_proxy or checkout_proxy
    checkout_billing = _oaics_checkout_billing(checkout, billing)
    if not stripe_pk.startswith("pk_live_"):
        raise RuntimeError(f"OAICS checkout 缺少 Stripe publishable_key: {cs_id[:24]}")
    if not customer_secret:
        raise RuntimeError(f"OAICS checkout 缺少 customer_session_client_secret: {cs_id[:24]}")
    try:
        methods = [
            str(item).strip().lower()
            for item in json.loads(str(checkout.get("payment_methods") or "[]"))
            if str(item or "").strip()
        ]
    except (TypeError, ValueError):
        methods = []
    if "upi" not in methods:
        raise RuntimeError(f"{UPI_METHOD_UNAVAILABLE_ERROR}: OAICS checkout payment_method_types={methods}")
    log(
        f"OAICS/UPI 链路开始: cs={cs_id[:28]}... provider=open_ai proxy={proxy_label(proxy)} "
        f"amount_due={_oaics_due_amount(checkout)}"
    )
    if promo_inject_pre_confirm_enabled():
        if str(checkout.get("promo_detected") or "0") == "1":
            log("confirm 前注入优惠开关已开启，但当前会话创建时已带优惠，直接沿用")
        else:
            log("confirm 前注入优惠开关已开启：先按原价创建会话，现注入优惠...")
            log(
                "注意：confirm 前注入优惠（原价会话→注入 0 元）实测 approve 后稳定"
                "返回 checkout_approval_internal_error（OpenAI 审批事务内部异常），"
                "拿不到 instructions；标准 0 元链（建单即带优惠）只会走 blocked 分支。"
                "如需继续 A/B 请对比两种链路。",
                "[WARN] ",
            )
            inject_chatgpt = build_chatgpt_session(
                access_token,
                device_id,
                proxy,
                session_token,
                fingerprint_profile=fingerprint,
            )
            try:
                updated = inject_promo_before_confirm(
                    inject_chatgpt,
                    checkout,
                    promotion_country=UPI_PROMOTION_COUNTRY,
                    billing=billing,
                )
                checkout.update(updated)
            finally:
                try:
                    inject_chatgpt.close()
                except Exception:
                    pass
            if _oaics_due_amount(checkout) != 0:
                raise RuntimeError(
                    f"{UPI_AMOUNT_NONZERO_ERROR}: confirm 前注入优惠未生效，"
                    f"当前 due={_oaics_due_amount(checkout)}"
                )
            log(f"注入后 OAICS checkout due={_oaics_due_amount(checkout)}，进入 0 元 confirm 链路")

    def chain_once(active_checkout: dict[str, Any]) -> tuple[str, list[str]]:
        active_cs = str(active_checkout.get("cs_id") or "").strip()
        active_customer_secret = str(active_checkout.get("customer_session_client_secret") or "").strip()
        active_pk = str(active_checkout.get("stripe_pk") or stripe_pk).strip()
        active_billing = _oaics_checkout_billing(active_checkout, billing)
        if stop_event and stop_event.is_set():
            raise RuntimeError("任务已停止，跳过本轮")
        chatgpt = build_chatgpt_session(
            access_token,
            device_id,
            proxy,
            session_token,
            fingerprint_profile=fingerprint,
        )
        stripe = new_session(proxy, use_pre_proxy=False, fingerprint_profile=fingerprint)
        try:
            stripe.headers.update(
                {
                    "User-Agent": _fingerprint_value(
                        fingerprint,
                        "ua",
                        "user_agent",
                        default=random_user_agent(),
                    ),
                    "Accept": "application/json",
                    "Accept-Language": payment_accept_language(),
                    "Origin": "https://js.stripe.com",
                    "Referer": "https://js.stripe.com/",
                }
            )
            stripe_js_id = stripe_browser_id()
            log(f"OAICS Stripe Elements: cs={active_cs[:24]}...")
            elements = _oaics_elements_session(
                stripe,
                stripe_pk=active_pk,
                customer_session_client_secret=active_customer_secret,
                amount=_oaics_due_amount(active_checkout),
                stripe_js_id=stripe_js_id,
                mandate_amount=(_oaics_mandate_amount_from_checkout(active_checkout) or None),
            )
            elements_session_id, elements_config_id = _oaics_elements_ids(elements)
            log(f"OAICS Elements 会话: session={elements_session_id[:32]} config={elements_config_id[:16]}")
            inline_token = official_inline_confirmation_token_enabled()
            pm_id = ""
            if inline_token:
                log("OAICS 官方内联模式：跳过独立 PM 创建，直接生成内联 ConfirmationToken")
            else:
                pm_id = _oaics_create_upi_pm(
                    stripe,
                    stripe_pk=active_pk,
                    cs_id=active_cs,
                    billing=active_billing,
                    stripe_js_id=stripe_js_id,
                    elements_session_id=elements_session_id,
                    elements_config_id=elements_config_id,
                )
                log(f"OAICS UPI PM 创建成功: {pm_id}")
            confirmation_token = _oaics_create_confirmation_token(
                stripe,
                stripe_pk=active_pk,
                cs_id=active_cs,
                pm_id=pm_id,
                stripe_js_id=stripe_js_id,
                elements_session_id=elements_session_id,
                elements_config_id=elements_config_id,
                billing=active_billing,
                inline=inline_token,
            )
            log(f"OAICS ConfirmationToken 创建成功: {confirmation_token}")
            confirm_payload = _oaics_chatgpt_confirm(
                chatgpt,
                cs_id=active_cs,
                processor_entity=processor_entity,
                confirmation_token=confirmation_token,
            )
            log(
                "OAICS checkout/confirm 成功: "
                f"type={confirm_payload.get('type')} status={confirm_payload.get('status')}"
            )
            intent_type = str(confirm_payload.get("type") or "").strip().lower()
            if (
                intent_type == "setup_intent"
                and not require_zero
                and not original_price_zero_fallback_enabled()
            ):
                # 原价链强制语义：命中 0 元分支直接判失败，不再重建 Checkout 绕圈，
                # 也不再尝试任何 0 元/试用判定。
                raise RuntimeError(
                    f"{UPI_ORIGINAL_PRICE_APPROVAL_REQUIRED}: OAICS 命中 0 元 "
                    "SetupIntent 分支：该账号在正价链路上仍被判成 0 元（自动试用/满减），"
                    "原价链无法交付正价支付链接。请更换无自动试用/折扣的账号走原价链，"
                    "或改用 0 元链。"
                )
            return _oaics_confirm_intent(
                stripe,
                stripe_pk=active_pk,
                confirm_payload=confirm_payload,
                confirmation_token=confirmation_token,
                stripe_js_id=stripe_js_id,
                cs_id=active_cs,
                require_zero=require_zero,
            )
        finally:
            try:
                chatgpt.close()
            except Exception:
                pass
            try:
                stripe.close()
            except Exception:
                pass

    # 原价链强制语义：命中 0 元/人工审批分支时 chain_once 会直接抛出
    # UPI_ORIGINAL_PRICE_APPROVAL_REQUIRED（账号级判定），这里不再重建 Checkout
    # 反复绕 0 元分支——那样既拿不到正价链，又白烧代理与 CDK。
    return chain_once(checkout)


def run_once(
    access_token: str,
    session_token: str,
    checkout_proxy: str,
    promotion_proxy: str,
    provider_proxy: str,
    approve_pool: list[str],
    attempt: int,
    max_retry: int,
    stop_event: Event | None = None,
) -> tuple[str, list[str]]:
    if stop_event and stop_event.is_set():
        raise RuntimeError("任务已停止，跳过本轮")
    fingerprint = resolve_attempt_upi_fingerprint(access_token, attempt)
    device_id = fingerprint["device_id"]
    checkout_country = normalize_country(os.environ.get("UPI_CHECKOUT_COUNTRY", UPI_BOOTSTRAP_COUNTRY))
    billing = upi_billing_profile(fingerprint.get("account_id", ""))
    log(f"开始 UPI 提取，第 {attempt}/{max_retry} 次")
    log(
        "组合测试: "
        f"{checkout_country} / {billing['country']} / {currency_for_country(checkout_country)} / "
        f"{payment_browser_locale()} / "
        f"{os.environ.get('UPI_PROVIDER_COUNTRY_LABEL', UPI_PROVIDER_COUNTRY).strip() or UPI_PROVIDER_COUNTRY}"
    )
    if stop_event and stop_event.is_set():
        raise RuntimeError("任务已停止，跳过本轮")

    try:
        proxy_seed = checkout_proxy
        checkout_proxy, promotion_proxy, provider_proxy = upi_proxy_chain(proxy_seed)
        log_upi_proxy_chain(proxy_seed, checkout_proxy, promotion_proxy, provider_proxy)
        log(f"本轮代理: checkout/资格={proxy_label(checkout_proxy)}；Stripe/UPI={proxy_label(provider_proxy)}")
        zero_status, zero_amount, _zero_checked_at = checkout_zero_cache_status(checkout_proxy, checkout_country)
        if zero_status == "ok":
            log(f"checkout 0元资格缓存命中: amount={zero_amount}")
        elif zero_status == "bad":
            log(f"checkout 0元失败缓存命中: 上次 amount={zero_amount}，本轮继续验证", "[WARN] ")
        chatgpt = build_chatgpt_session(
            access_token,
            device_id,
            checkout_proxy,
            session_token,
            fingerprint_profile=fingerprint,
        )
        account_id = str(fingerprint.get("account_id") or "").strip()
        require_zero = env_bool("UPI_REQUIRE_ZERO", True)
        if require_zero and env_bool("UPI_ZERO_ELIGIBILITY_PRECHECK", True):
            ensure_upi_zero_eligible(chatgpt, account_id)
        checkout = create_checkout(
            chatgpt,
            checkout_country,
            promo_override="off" if promo_inject_pre_confirm_enabled() else "",
            billing=billing,
        )
    except Exception as exc:
        if is_user_already_paid_error(exc):
            raise RuntimeError("用户已支付: User is already paid") from exc
        if is_checkout_not_active_error(exc):
            raise
        raise RuntimeError(f"checkout 阶段失败: {exc}") from exc
    account_id = str(fingerprint.get("account_id") or "").strip()
    try:
        return run_provider_flow(
            access_token,
            session_token,
            checkout_proxy,
            promotion_proxy,
            provider_proxy,
            [provider_proxy],
            device_id,
            checkout,
            billing,
            stop_event,
            fingerprint,
        )
    except Exception as exc:
        if UPI_AMOUNT_NONZERO_ERROR in str(exc) and env_bool("UPI_ZERO_NEGATIVE_CACHE", True):
            _mark_zero_ineligible(account_id)
            log("0 元金额未生效，已记录账号 0 元资格负缓存", "[WARN] ")
        raise


def run_attempt(
    access_token: str,
    session_token: str,
    checkout_proxy: str,
    promotion_proxy: str,
    provider_proxy: str,
    approve_pool: list[str],
    attempt: int,
    max_retry: int,
    stop_event: Event | None = None,
    batch_no: int = 0,
    batch_total: int = 0,
) -> tuple[int, str, list[str], str, str, str]:
    previous_log_context = getattr(_log_context, "prefix", "")
    if batch_no > 0:
        _log_context.prefix = f"[批次 {batch_no}/{batch_total or '?'}][轮次 {attempt}/{max_retry}] "
    else:
        _log_context.prefix = f"[轮次 {attempt}/{max_retry}] "
    try:
        redirect_url, qr_urls = run_once(
            access_token,
            session_token,
            checkout_proxy,
            promotion_proxy,
            provider_proxy,
            approve_pool,
            attempt,
            max_retry,
            stop_event,
        )
        has_result = bool(redirect_url)
        if has_result and stop_event:
            stop_event.set()
        if has_result:
            record_proxy_pair_result(checkout_proxy, provider_proxy, True, "success")
        else:
            record_proxy_result("provider", provider_proxy, False, "no_redirect_url")
        _log_context.prefix = previous_log_context
        return attempt, redirect_url, qr_urls, checkout_proxy, provider_proxy, ""
    except Exception as exc:
        error = str(exc)
        if error.startswith("任务已停止"):
            _log_context.prefix = previous_log_context
            return attempt, "", [], checkout_proxy, provider_proxy, ""
        if is_user_already_paid_error(error):
            log("检测到 User is already paid：用户已支付，停止任务")
            if stop_event:
                stop_event.set()
            _log_context.prefix = previous_log_context
            return attempt, "", [], checkout_proxy, provider_proxy, error
        if is_upi_unavailable_error(error):
            log(f"第 {attempt}/{max_retry} 轮 checkout 未提供 UPI，保留代理并继续后续组合", "[WARN] ")
            _log_context.prefix = previous_log_context
            return attempt, "", [], checkout_proxy, provider_proxy, error
        if is_checkout_not_active_error(error):
            log(
                f"第 {attempt}/{max_retry} 轮 Session 已失效；跳过本轮，不记录代理失败，代理保留供后续使用",
                "[WARN] ",
            )
            _log_context.prefix = previous_log_context
            return attempt, "", [], checkout_proxy, provider_proxy, error
        record_failure_by_stage(error, checkout_proxy, provider_proxy, promotion_proxy)
        log(f"第 {attempt}/{max_retry} 轮失败: {error[:300]}", "[WARN] ")
        _log_context.prefix = previous_log_context
        return attempt, "", [], checkout_proxy, provider_proxy, error


def successful_pair_preferences(checkout_proxies: list[str], provider_proxies: list[str]) -> dict[str, list[str]]:
    if not env_bool("UPI_PROXY_SCORE", True):
        return {}
    checkout_by_key = {proxy_key(proxy): proxy for proxy in checkout_proxies}
    provider_by_key = {proxy_key(proxy): proxy for proxy in provider_proxies}
    pair_state = load_proxy_state().get("pair", {})
    if not isinstance(pair_state, dict):
        return {}

    candidates: list[tuple[int, int, str, str]] = []
    for record in pair_state.values():
        if not isinstance(record, dict):
            continue
        success_count = int(record.get("success") or 0)
        if success_count <= 0:
            continue
        checkout_proxy = checkout_by_key.get(str(record.get("checkout") or ""))
        provider_proxy = provider_by_key.get(str(record.get("provider") or ""))
        if checkout_proxy and provider_proxy:
            candidates.append((success_count, int(record.get("last_success") or 0), checkout_proxy, provider_proxy))

    candidates.sort(reverse=True)
    preferences: dict[str, list[str]] = {}
    for _success_count, _last_success, checkout_proxy, provider_proxy in candidates:
        providers = preferences.setdefault(checkout_proxy, [])
        if provider_proxy not in providers:
            providers.append(provider_proxy)
    return preferences


def build_attempt_batches(checkout_proxies: list[str], provider_proxies: list[str], max_attempts: int) -> list[tuple[str, list[str]]]:
    per_checkout = env_int("UPI_PROVIDER_PER_CHECKOUT", 30)
    provider_pool = provider_proxies[:]
    preferred_pairs = successful_pair_preferences(checkout_proxies, provider_proxies)
    reserved_provider_owner: dict[str, str] = {}
    for checkout_proxy, preferred_providers in preferred_pairs.items():
        for provider_proxy in preferred_providers:
            reserved_provider_owner.setdefault(provider_proxy, checkout_proxy)
    used_providers: set[str] = set()
    batches: list[tuple[str, list[str]]] = []
    provider_index = 0
    attempt_count = 0
    preferred_count = 0
    for checkout_proxy in checkout_proxies:
        batch: list[str] = []
        for provider_proxy in preferred_pairs.get(checkout_proxy, []):
            if len(batch) >= per_checkout or attempt_count >= max_attempts:
                break
            if provider_proxy in used_providers:
                continue
            batch.append(provider_proxy)
            used_providers.add(provider_proxy)
            attempt_count += 1
            preferred_count += 1
        while len(batch) < per_checkout and provider_index < len(provider_pool) and attempt_count < max_attempts:
            provider_proxy = provider_pool[provider_index]
            provider_index += 1
            if provider_proxy in used_providers:
                continue
            reserved_owner = reserved_provider_owner.get(provider_proxy)
            if reserved_owner and reserved_owner != checkout_proxy:
                continue
            batch.append(provider_proxy)
            used_providers.add(provider_proxy)
            attempt_count += 1
        if batch:
            batches.append((checkout_proxy, batch))
        if attempt_count >= max_attempts:
            break
    if preferred_count:
        log(f"调度命中成功组合优先: {preferred_count} 组")
    return batches


def is_preferred_proxy(group: str, proxy: str) -> bool:
    if not group or not env_bool("UPI_PROXY_SCORE", True):
        return False
    state = load_proxy_state().get(group, {})
    if not isinstance(state, dict):
        return False
    record = state.get(proxy_key(proxy), {})
    if not isinstance(record, dict):
        return False
    return int(record.get("success") or 0) > 0


def pick_random_proxies(proxies: list[str], limit: int, group: str = "") -> list[str]:
    if group:
        proxies = order_proxy_group(group, proxies)
    preferred = [proxy for proxy in proxies if is_preferred_proxy(group, proxy)]
    preferred_set = set(preferred)
    rest = [proxy for proxy in proxies if proxy not in preferred_set]
    if limit >= len(proxies):
        random.shuffle(rest)
        return preferred + rest
    selected = preferred[:limit]
    remain_count = limit - len(selected)
    if remain_count > 0:
        selected.extend(random.sample(rest, min(remain_count, len(rest))))
    return selected


def run_single_link_attempt(
    access_token: str,
    session_token: str,
    checkout_proxies: list[str],
    promotion_proxies: list[str],
    provider_proxies: list[str],
    attempt: int,
    upi_retry: int,
    checkout_retry: int,
    provider_retry: int,
    checkout_country: str,
    checkout_currency: str,
    stop_event: Event,
) -> tuple[int, str, str, bool]:
    previous_log_context = getattr(_log_context, "prefix", "")
    _log_context.prefix = f"[UPI {attempt}/{upi_retry}] "
    last_error = ""
    approve_blocked = False
    checkout_proxy_used = ""
    try:
        if stop_event.is_set():
            return attempt, "", "任务已停止，跳过本轮", False
        fingerprint = resolve_attempt_upi_fingerprint(access_token, attempt)
        device_id = fingerprint["device_id"]
        billing = upi_billing_profile(fingerprint.get("account_id", ""))
        pm_country = billing["country"]
        checkout_candidates = pick_random_proxies(checkout_proxies, checkout_retry, "checkout")
        checkout: dict[str, str] | None = None
        promotion_proxy = ""
        provider_proxy = ""

        log(f"开始第 {attempt}/{upi_retry} 次提链")
        log(
            f"Step 1: 创建 ChatGPT checkout... checkout账单={checkout_country}/{checkout_currency}，"
            f"第 {attempt}/{upi_retry} 次，每次随机抽取最多 {checkout_retry} 个节点"
        )
        log(f"首次 PM 国家: {pm_country}")

        for checkout_index, proxy_seed in enumerate(checkout_candidates, start=1):
            if stop_event.is_set():
                return attempt, "", "任务已停止，跳过本轮", False
            _log_context.prefix = f"[UPI {attempt}/{upi_retry}][PM={pm_country}] "
            try:
                if checkout_index > 1:
                    fingerprint = resolve_attempt_upi_fingerprint(
                        access_token,
                        attempt,
                        checkout_retry_index=checkout_index - 1,
                    )
                    device_id = fingerprint["device_id"]
                checkout_proxy, promotion_proxy, provider_proxy = upi_proxy_chain(proxy_seed)
                log_upi_proxy_chain(proxy_seed, checkout_proxy, promotion_proxy, provider_proxy)
                log(f"Checkout {checkout_index}/{len(checkout_candidates)}: {checkout_country}/{checkout_currency}, proxy={proxy_label(checkout_proxy)}")
                zero_status, zero_amount, _zero_checked_at = checkout_zero_cache_status(checkout_proxy, checkout_country)
                if zero_status == "ok":
                    log(f"checkout 0元资格缓存命中: amount={zero_amount}")
                elif zero_status == "bad":
                    log(f"checkout 0元失败缓存命中: 上次 amount={zero_amount}，本轮继续验证", "[WARN] ")
                chatgpt = build_chatgpt_session(
                    access_token,
                    device_id,
                    checkout_proxy,
                    session_token,
                    fingerprint_profile=fingerprint,
                )
                checkout = create_checkout(
                    chatgpt,
                    checkout_country,
                    promo_override="off" if promo_inject_pre_confirm_enabled() else "",
                    billing=billing,
                )
                checkout_proxy_used = checkout_proxy
                break
            except Exception as exc:
                error = str(exc)
                last_error = error
                if is_user_already_paid_error(error):
                    log("检测到 User is already paid：用户已支付，停止任务")
                    stop_event.set()
                    return attempt, "", error, False
                if not is_checkout_not_active_error(error):
                    record_failure_by_stage(f"checkout 阶段失败: {error}", checkout_proxy, "")
                log(f"Checkout {checkout_index}/{len(checkout_candidates)} 失败: {error[:220]}", "[WARN] ")

        _log_context.prefix = f"[UPI {attempt}/{upi_retry}] "
        if not checkout or not checkout_proxy_used:
            log(f"第 {attempt}/{upi_retry} 次提链 checkout 阶段失败", "[WARN] ")
            return attempt, "", last_error or "checkout_failed", False

        stripe_pk = checkout.get("stripe_pk") or DEFAULT_STRIPE_PK
        log(f"Stripe PK: {stripe_pk[:18]}...")
        log(f"Step 2: 首次尝试 PM={pm_country}...")

        if stop_event.is_set():
            return attempt, "", "任务已停止，跳过本轮", False
        _log_context.prefix = f"[UPI {attempt}/{upi_retry}][PM={pm_country}] "
        try:
            redirect_url, _qr_urls = run_provider_flow(
                access_token,
                session_token,
                checkout_proxy_used,
                promotion_proxy,
                provider_proxy,
                [provider_proxy],
                device_id,
                checkout,
                billing,
                stop_event,
                fingerprint,
            )
            if redirect_url:
                record_proxy_pair_result(checkout_proxy_used, provider_proxy, True, "success")
                stop_event.set()
                return attempt, redirect_url, "", False
            last_error = "no_redirect_url"
            record_proxy_result("provider", provider_proxy, False, last_error)
        except Exception as exc:
            error = str(exc)
            last_error = error
            if is_checkout_not_active_error(error):
                log("Session 已失效；当前 checkout 不再继续换 provider", "[WARN] ")
            elif is_upi_unavailable_error(error):
                log("当前 checkout 未提供 UPI，换下一轮 checkout 组合", "[WARN] ")
                return attempt, "", error, False
            else:
                record_failure_by_stage(error, checkout_proxy_used, provider_proxy, promotion_proxy)
                log(f"Provider 失败: {error[:220]}", "[WARN] ")
                if is_approve_failure_error(error) and "approve blocked" in error:
                    approve_blocked = True

        _log_context.prefix = f"[UPI {attempt}/{upi_retry}] "
        log(f"第 {attempt}/{upi_retry} 次提链结束，未拿到最终 URL", "[WARN] ")
        return attempt, "", last_error, approve_blocked
    finally:
        _log_context.prefix = previous_log_context


def run_single_link_parallel_mode(
    access_token: str,
    session_token: str,
    checkout_proxies: list[str],
    promotion_proxies: list[str],
    provider_proxies: list[str],
) -> int:
    checkout_retry = env_int("UPI_CHECKOUT_RETRY_MAX", 5)
    provider_retry = env_int("UPI_PROVIDER_RETRY_MAX", 3)
    upi_retry = env_int("UPI_MAX_RETRY", 5)
    requested_workers = env_int("UPI_WORKERS", 1)
    worker_limit = env_int("UPI_WORKERS_MAX", requested_workers)
    workers = min(max(1, requested_workers), max(1, worker_limit), upi_retry)
    checkout_country = normalize_country(os.environ.get("UPI_CHECKOUT_COUNTRY", UPI_BOOTSTRAP_COUNTRY))
    checkout_currency = currency_for_country(checkout_country)
    configured_pm_country = normalize_country(
        os.environ.get("UPI_BILLING_COUNTRY", UPI_PROVIDER_COUNTRY)
    )
    max_blocked = env_int("UPI_MAX_APPROVE_BLOCKED", 1)
    approve_blocked_count = 0
    last_error = ""
    stop_event = Event()

    if requested_workers > workers:
        log(f"UPI并发从 {requested_workers} 限制为 {workers}", "[WARN] ")
    log(
        "开始执行 UPI 链提取流程："
        f"checkout={checkout_country}/{checkout_currency}，PM={configured_pm_country}，locale={payment_browser_locale()}，"
        f"Checkout重试={checkout_retry}，Provider重试={provider_retry}，UPI总重试={upi_retry}，UPI并发={workers}。"
    )

    executor = ThreadPoolExecutor(max_workers=workers)
    futures: dict[Any, int] = {}
    try:
        for attempt in range(1, upi_retry + 1):
            futures[
                executor.submit(
                    run_single_link_attempt,
                    access_token,
                    session_token,
                    checkout_proxies,
                    promotion_proxies,
                    provider_proxies,
                    attempt,
                    upi_retry,
                    checkout_retry,
                    provider_retry,
                    checkout_country,
                    checkout_currency,
                    stop_event,
                )
            ] = attempt

        for future in as_completed(futures):
            try:
                attempt, redirect_url, error, approve_blocked = future.result()
            except Exception as exc:
                attempt = futures.get(future, 0)
                redirect_url = ""
                error = str(exc)
                approve_blocked = False
                log(f"第 {attempt}/{upi_retry} 次提链异常: {error[:300]}", "[WARN] ")
            if redirect_url:
                stop_event.set()
                for pending in futures:
                    pending.cancel()
                print("\n===== 结果 =====")
                print(f"UPI 最终支付 URL:\n{delivery_result_url(redirect_url)}")
                return 0
            last_error = error or last_error
            if is_user_already_paid_error(error):
                log("检测到 User is already paid：用户已支付，任务正常结束")
                stop_event.set()
                for pending in futures:
                    pending.cancel()
                return 0
            if is_account_level_failure(error) or is_terminal_approval_error(error):
                # 账号级失败：换出口无意义，停止同号剩余轮次。
                log(f"全部失败: {error}", "[ERROR] ")
                stop_event.set()
                for pending in futures:
                    pending.cancel()
                return 1
            if is_account_level_original_price_failure(error):
                # 账号级：原价链仍被判成 0 元，换出口无用，停止同号整链重试。
                # 同样带 [ERROR] 前缀，让父进程能取到真实原因。
                log(
                    f"全部失败: {error}",
                    "[ERROR] ",
                )
                stop_event.set()
                for pending in futures:
                    pending.cancel()
                return 1
            if approve_blocked:
                approve_blocked_count += 1
                log(f"approve blocked 计数: {approve_blocked_count}/{max_blocked}", "[WARN] ")
            if approve_blocked_count >= max_blocked:
                log(
                    "达到当前账号 approve blocked 上限，停止继续提交新提链；"
                    "blocked 属于 OpenAI 0 元人工审批风控（官方 UI 同样提示 Payment was not approved），"
                    "建议更换新账号或改走正价 UPI 路径，同号继续重试只会重复同一 dead path",
                    "[WARN] ",
                )
                stop_event.set()
                for pending in futures:
                    pending.cancel()
                return 1
    finally:
        executor.shutdown(wait=True, cancel_futures=stop_event.is_set())

    log(f"全部失败: {last_error}", "[ERROR] ")
    return 1


def run_single_link_mode(
    access_token: str,
    session_token: str,
    proxy_seeds: list[str],
) -> int:
    upi_workers = env_int("UPI_WORKERS", 1)
    if upi_workers > 1:
        log(f"UPI 链路固定并发=1，忽略 UPI_WORKERS={upi_workers}", "[WARN] ")

    checkout_retry = env_int("UPI_CHECKOUT_RETRY_MAX", 5)
    provider_retry = env_int("UPI_PROVIDER_RETRY_MAX", 3)
    upi_retry = env_int("UPI_MAX_RETRY", 5)
    # 网络/代理层可换出口重试：TLS 握手失败、超时、连接被重置等不代表账号死亡，
    # 只要本任务还有没试过的 Seed 就应该继续换，而不是直接把这个号判失败。
    transport_retry_budget = env_int("UPI_TRANSPORT_RETRY_MAX", 4, minimum=0)
    checkout_country = normalize_country(os.environ.get("UPI_CHECKOUT_COUNTRY", UPI_BOOTSTRAP_COUNTRY))
    checkout_currency = currency_for_country(checkout_country)
    configured_pm_country = normalize_country(
        os.environ.get("UPI_BILLING_COUNTRY", UPI_PROVIDER_COUNTRY)
    )
    max_blocked = env_int("UPI_MAX_APPROVE_BLOCKED", 1)
    risk_control_max = env_int("UPI_RISK_CONTROL_MAX", 2, minimum=1)
    approve_blocked_count = 0
    risk_control_failures = 0
    risk_control_proxy_keys: set[str] = set()
    risk_control_fingerprint_keys: set[str] = set()
    last_error = ""
    stop_event = Event()
    attempted_seed_keys: set[str] = set()
    lease_busy_hits = 0
    transport_rotations = 0
    # 代理层失败（TLS/超时/连接重置）后置位，允许在预算内重置已尝试 Seed 换出口。
    transport_rotations_needed = False

    def record_risk_control(
        error: str,
        *,
        phase: str,
        proxy_seed: str,
        fingerprint: dict[str, Any],
    ) -> bool:
        nonlocal last_error, risk_control_failures
        if not is_upstream_risk_control_error(error):
            return False
        risk_control_failures += 1
        seed_key = proxy_chain_key(proxy_seed)
        if seed_key:
            risk_control_proxy_keys.add(seed_key)
        fingerprint_key = ":".join(
            str(fingerprint.get(key) or "").strip()
            for key in ("fingerprint_id", "device_id")
        ).strip(":")
        if fingerprint_key:
            risk_control_fingerprint_keys.add(fingerprint_key)
        last_error = risk_control_failure_message(
            phase,
            risk_control_failures,
            risk_control_proxy_keys,
            fingerprint,
            risk_control_fingerprint_keys,
        )
        log(
            f"检测到 {phase} 上游风控：unusual activity，"
            f"累计={risk_control_failures}/{risk_control_max}，"
            f"不同代理 Seed={len(risk_control_proxy_keys)}，"
            f"不同指纹会话={len(risk_control_fingerprint_keys)}，"
            f"指纹模式={fingerprint.get('mode') or 'sticky'}",
            "[WARN] ",
        )
        if risk_control_failures < risk_control_max:
            return False
        log(
            f"连续命中上游风控，停止当前任务级重试：{last_error}",
            "[ERROR] ",
        )
        return True

    log(
        "开始执行 UPI 链提取流程："
        f"checkout={checkout_country}/{checkout_currency}，PM={configured_pm_country}，locale={payment_browser_locale()}，"
        f"Checkout重试={checkout_retry}，Provider重试={provider_retry}，UPI总重试={upi_retry}，"
        f"连续风控阈值={risk_control_max}。"
    )

    for attempt in range(1, upi_retry + 1):
        # 网络层失败（TLS/超时/连接重置）允许在预算内重新抽取新 Seed。
        remaining_seeds = [
            proxy_seed
            for proxy_seed in proxy_seeds
            if proxy_chain_key(proxy_seed) not in attempted_seed_keys
        ]
        if (
            attempt > 1
            and not remaining_seeds
            and transport_rotations_needed
            and transport_retry_budget > 0
        ):
            if transport_rotations < transport_retry_budget:
                transport_rotations += 1
                transport_rotations_needed = False
                log(
                    "网络层失败重试：本任务 Seed 已用完，"
                    f"第 {transport_rotations}/{transport_retry_budget} 次重置已尝试 Seed，"
                    "换新出口继续（不代表账号失败）",
                    "[WARN] ",
                )
                attempted_seed_keys.clear()
            else:
                log(
                    f"网络层失败重试预算已用完（{transport_retry_budget} 次），停止继续换出口",
                    "[WARN] ",
                )
        fingerprint = resolve_attempt_upi_fingerprint(access_token, attempt)
        device_id = fingerprint["device_id"]
        billing = upi_billing_profile(fingerprint.get("account_id", ""))
        pm_country = billing["country"]
        available_seeds = [
            proxy_seed
            for proxy_seed in proxy_seeds
            if proxy_chain_key(proxy_seed) not in attempted_seed_keys
        ]
        # 并发匹配：优先把当前没被其它任务占用的 Seed 排到前面，避免候选
        # 全是「已被占用」的出口导致整轮空转。
        free_seeds = [
            item for item in available_seeds if not lease_in_use(item)
        ]
        # 全部候选都被其它任务占用时，短等待重扫（而不是立刻判失败）：
        # 高并发下同一时刻池子被占满是暂时的，等几秒通常就有出口释放。
        if not free_seeds and available_seeds:
            busy_wait = env_int("UPI_PROXY_LEASE_BUSY_WAIT", 20, minimum=0)
            waited = 0.0
            while waited < busy_wait and not stop_event.is_set():
                time.sleep(1.0)
                waited += 1.0
                free_seeds = [
                    item for item in available_seeds if not lease_in_use(item)
                ]
                if free_seeds:
                    log(
                        f"UPI Seed 全被并发占用，等待 {int(waited)}s 后出现空闲出口，继续提链",
                        "[WARN] ",
                    )
                    break
            else:
                if busy_wait:
                    log(
                        f"UPI Seed 在 {busy_wait}s 内始终被其它任务占用，本轮跳过并重试",
                        "[WARN] ",
                    )
        ordered_seeds = free_seeds + [
            item for item in available_seeds if item not in set(free_seeds)
        ]
        checkout_candidates = pick_random_proxies(
            ordered_seeds, checkout_retry, "seed"
        )
        if not checkout_candidates:
            last_error = last_error or "本次任务的代理 Seed 已全部尝试"
            log("本次任务的代理 Seed 已全部尝试，不再重复失败节点", "[WARN] ")
            break
        # 极端并发下所有候选可能同时被别的任务拿着：此时先按 Seed 重新随机抽取
        # 几轮（每轮候选数翻倍），而不是立刻判「暂无空闲代理 Seed」结束任务。
        if (
            proxy_lease_wait() <= 0
            and len(proxy_seeds) > len(checkout_candidates)
            and attempt <= env_int("UPI_PROXY_LEASE_RESAMPLE_ROUNDS", 3, minimum=0)
        ):
            extra_rounds = max(1, min(5, len(proxy_seeds) // max(1, checkout_retry)))
            for resample_index, extra_count in enumerate(
                range(checkout_retry * 2, len(proxy_seeds) + 1, max(1, checkout_retry)),
                start=1,
            ):
                if resample_index > extra_rounds:
                    break
                resampled = [
                    proxy_seed
                    for proxy_seed in available_seeds
                    if proxy_chain_key(proxy_seed) not in attempted_seed_keys
                ]
                if not resampled:
                    break
                checkout_candidates = pick_random_proxies(
                    resampled, min(extra_count, len(resampled)), "seed"
                )
                free_keys = [
                    proxy_chain_key(proxy_seed)
                    for proxy_seed in checkout_candidates
                    if proxy_chain_key(proxy_seed) not in attempted_seed_keys
                ]
                if free_keys:
                    break
            if checkout_candidates:
                log(
                    f"Seed 占用重抽：本轮候选已扩大到 {len(checkout_candidates)} 条"
                    "（并发占用导致原候选不可用）",
                    "[WARN] ",
                )
        checkout: dict[str, str] | None = None
        checkout_proxy_used = ""
        checkout_seed_used = ""
        # 当前 attempt 已持有租约的 Seed；失败/租约丢失时统一在这里释放并
        # 移出候选，保证下一次提链一定换全新出口。
        checkout_seed_held = ""
        promotion_proxy = ""
        provider_proxy = ""
        checkout_lease: ProxySeedLease | None = None

        def _discard_held_seed(reason: str) -> None:
            # 必须同时声明 checkout_lease：闭包里对它赋值会让它变成局部变量，
            # 读取时直接抛 UnboundLocalError，把真实失败原因（approve blocked /
            # UPI_AMOUNT_NONZERO）覆盖成无意义的 "referenced before assignment"。
            nonlocal checkout_seed_held, checkout_lease
            if checkout_lease:
                checkout_lease.release()
                checkout_lease = None
            if checkout_seed_held:
                held_key = proxy_chain_key(checkout_seed_held)
                attempted_seed_keys.add(held_key)
                log(
                    f"{reason}：Seed={held_key or proxy_label(checkout_seed_held)} "
                    "租约已释放并移出候选，下一次提链将重抽新出口",
                    "[WARN] ",
                )
                checkout_seed_held = ""

        log(f"开始第 {attempt}/{upi_retry} 次提链")
        log(
            f"Step 1: 创建 ChatGPT checkout... checkout账单={checkout_country}/{checkout_currency}，"
            f"第 {attempt}/{upi_retry} 次，每次随机抽取最多 {checkout_retry} 个节点"
        )
        log(f"  首次 PM 国家: {pm_country}")

        for checkout_index, proxy_seed in enumerate(checkout_candidates, start=1):
            previous_log_context = getattr(_log_context, "prefix", "")
            _log_context.prefix = f"  [PM={pm_country}] "
            checkout_proxy = ""
            promotion_proxy = ""
            provider_proxy = ""
            chain_key = proxy_chain_key(proxy_seed)
            attempted_seed_keys.add(chain_key)
            record_exit_usage(proxy_seed)
            candidate_lease = ProxySeedLease(proxy_seed)
            if not candidate_lease.acquire():
                lease_busy_hits += 1
                log(
                    f"Checkout {checkout_index}/{len(checkout_candidates)} 跳过："
                    f"Seed={chain_key or proxy_label(proxy_seed)} 已被其它 UPI 任务占用",
                    "[WARN] ",
                )
                last_error = "UPI_PROXY_LEASE_BUSY"
                # 租约被占 ≠ 出口故障：把 Seed 还给候选池，先按配置的等待窗口
                # 等租约释放，等不到就从剩余未尝试 Seed 里补抽，避免白白烧掉
                # 一次候选名额（大池高并发下这是「暂无空闲代理 Seed」的主因）。
                attempted_seed_keys.discard(chain_key)
                if proxy_lease_wait() > 0:
                    waited_lease = ProxySeedLease(proxy_seed)
                    if waited_lease.acquire():
                        candidate_lease = waited_lease
                        attempted_seed_keys.add(chain_key)
                        lease_busy_hits -= 1
                        log(
                            f"Checkout {checkout_index}/{len(checkout_candidates)} "
                            f"等待后取得租约：Seed={chain_key or proxy_label(proxy_seed)}"
                        )
                if not (candidate_lease and candidate_lease.acquired):
                    untried = [
                        item
                        for item in proxy_seeds
                        if proxy_chain_key(item) not in attempted_seed_keys
                    ]
                    if untried:
                        proxy_seed = random.choice(untried)
                        chain_key = proxy_chain_key(proxy_seed)
                        attempted_seed_keys.add(chain_key)
                        record_exit_usage(proxy_seed)
                        candidate_lease = ProxySeedLease(proxy_seed)
                        if candidate_lease.acquire():
                            lease_busy_hits -= 1
                            log(
                                f"Checkout {checkout_index}/{len(checkout_candidates)} "
                                f"补抽空闲 Seed：{chain_key or proxy_label(proxy_seed)}"
                                f"（剩余未尝试 {len(untried) - 1} 条）"
                            )
                        else:
                            candidate_lease = None
                    else:
                        candidate_lease = None
                if not (candidate_lease and candidate_lease.acquired):
                    continue
            try:
                if checkout_index > 1:
                    fingerprint = resolve_attempt_upi_fingerprint(
                        access_token,
                        attempt,
                        checkout_retry_index=checkout_index - 1,
                    )
                    device_id = fingerprint["device_id"]
                checkout_proxy, promotion_proxy, provider_proxy = upi_proxy_chain(proxy_seed)
                log_upi_proxy_chain(proxy_seed, checkout_proxy, promotion_proxy, provider_proxy)
                log(
                    f"Checkout {checkout_index}/{len(checkout_candidates)}: "
                    f"{checkout_country}/{checkout_currency}, proxy={proxy_label(checkout_proxy)}，"
                    f"本次已尝试 Seed={len(attempted_seed_keys)}"
                )
                zero_status, zero_amount, _zero_checked_at = checkout_zero_cache_status(checkout_proxy, checkout_country)
                if zero_status == "ok":
                    log(f"checkout 0元资格缓存命中: amount={zero_amount}")
                elif zero_status == "bad":
                    log(f"checkout 0元失败缓存命中: 上次 amount={zero_amount}，本轮继续验证", "[WARN] ")
                chatgpt = build_chatgpt_session(
                    access_token,
                    device_id,
                    checkout_proxy,
                    session_token,
                    fingerprint_profile=fingerprint,
                )
                checkout = create_checkout(
                    chatgpt,
                    checkout_country,
                    promo_override="off" if promo_inject_pre_confirm_enabled() else "",
                    billing=billing,
                )
                checkout_proxy_used = checkout_proxy
                checkout_seed_used = proxy_seed
                checkout_seed_held = proxy_seed
                checkout_lease = candidate_lease
                log(
                    f"Seed 租约已获取：{chain_key or proxy_label(proxy_seed)}，"
                    f"TTL={proxy_lease_ttl()}s"
                )
                break
            except Exception as exc:
                candidate_lease.release()
                error = str(exc)
                last_error = error
                if is_user_already_paid_error(error):
                    log("检测到 User is already paid：用户已支付，任务正常结束")
                    return 0
                risk_control = is_upstream_risk_control_error(error)
                if risk_control:
                    if record_risk_control(
                        error,
                        phase="checkout",
                        proxy_seed=proxy_seed,
                        fingerprint=fingerprint,
                    ):
                        return 1
                elif not is_checkout_not_active_error(error):
                    if is_proxy_health_failure(error):
                        # TLS 握手失败 / 超时 / 连接重置属于出口问题：换 Seed 重试，
                        # 不要把这个号直接判失败（用户只看到一句错误就停任务）。
                        transport_rotations_needed = True
                        log(
                            f"该出口网络层失败（{error[:120]}），已记为可换出口重试，"
                            "本任务会继续尝试其它 Seed",
                            "[WARN] ",
                        )
                    elif is_account_auth_error(error):
                        # AT 过期/失效：换 Seed、换指纹都救不回来，立即停止整条链路，
                        # 并且不记代理失败（见 record_failure_by_stage 的账号级豁免）。
                        log(
                            f"{UPI_ACCOUNT_AUTH_EXPIRED}: 账号凭证已失效"
                            f"（OpenAI 返回 {error[:180]}）；已停止该账号剩余轮次，"
                            "未消耗其它代理出口。请删除该账号并重新导入新的 AT。",
                            "[ERROR] ",
                        )
                        last_error = (
                            f"{UPI_ACCOUNT_AUTH_EXPIRED}: access token 已失效，"
                            "请删除该账号并重新导入新的 AT"
                        )
                        return 1
                    record_failure_by_stage(
                        f"checkout 阶段失败: {error}",
                        checkout_proxy or proxy_seed,
                        "",
                    )
                log(f"Checkout {checkout_index}/{len(checkout_candidates)} 失败: {error[:220]}", "[WARN] ")
            finally:
                _log_context.prefix = previous_log_context

        if not checkout or not checkout_proxy_used:
            if last_error and is_proxy_health_failure(last_error):
                transport_rotations_needed = True
                log(
                    f"第 {attempt}/{upi_retry} 次提链 checkout 阶段因出口网络层失败中断，"
                    "下一轮会换新 Seed（不影响账号本身）",
                    "[WARN] ",
                )
            else:
                log(f"第 {attempt}/{upi_retry} 次提链 checkout 阶段失败，换下一次提链", "[WARN] ")
            continue

        stripe_pk = checkout.get("stripe_pk") or DEFAULT_STRIPE_PK
        log(f"Stripe PK: {stripe_pk[:18]}...")
        log(f"Step 2: 首次尝试 PM={pm_country}...")

        if checkout_lease and not checkout_lease.refresh():
            log("UPI 代理租约已丢失，停止复用当前 checkout，转入下一次提链", "[WARN] ")
            _discard_held_seed("代理租约被其它任务抢占")
            last_error = "UPI_PROXY_LEASE_LOST"
            continue

        previous_log_context = getattr(_log_context, "prefix", "")
        _log_context.prefix = f"  [PM={pm_country}] "
        try:
            redirect_url, _qr_urls = run_provider_flow(
                access_token,
                session_token,
                checkout_proxy_used,
                promotion_proxy,
                provider_proxy,
                [provider_proxy],
                device_id,
                checkout,
                billing,
                stop_event,
                fingerprint,
            )
            if redirect_url:
                # 交付前强制校验：UPI instructions 链是一次性支付动作，
                # Stripe 会把未在窗口内完成授权的委托判 abandoned → canceled。
                # 若不校验就当成功交付，用户拿到的是一条打得开但付不了钱的死链。
                dead_reason = upi_delivery_dead_reason(redirect_url, _qr_urls)
                if dead_reason:
                    last_error = dead_reason
                    log(f"本轮提链产出的 UPI 链已失效，不作为成功交付：{dead_reason}", "[WARN] ")
                    record_proxy_result("seed", checkout_proxy_used, False, "upi_link_dead")
                    continue
                record_proxy_result("seed", checkout_proxy_used, True, "success")
                record_exit_success(checkout_proxy_used or provider_proxy)
                print("\n===== 结果 =====")
                print(
                    f"UPI 最终支付 URL:\n{delivery_result_url(redirect_url, _qr_urls)}"
                )
                log_upi_delivery_validity(redirect_url, _qr_urls)
                return 0
            last_error = "no_redirect_url"
            record_proxy_result("seed", provider_proxy, False, last_error)
        except Exception as exc:
            error = str(exc)
            last_error = error
            if is_checkout_not_active_error(error):
                log("Session 已失效；当前 checkout 不再继续换 provider", "[WARN] ")
            elif is_upi_unavailable_error(error):
                log("当前 checkout 未提供 UPI，换下一次提链", "[WARN] ")
            elif is_account_level_failure(error) or is_terminal_approval_error(error):
                # 账号级失败：换出口/换指纹不会改变判定（approve blocked /
                # 促销不生效 / Stripe 拒绝建委托），直接停止该账号的剩余轮次，
                # 避免把 4 轮全部耗在同一个 dead path 上。
                # 出口层失败（TLS/超时/连接重置）不走这条，会继续换 Seed。
                log(
                    f"全部失败: {error}",
                    "[ERROR] ",
                )
                return 1
            elif is_account_level_original_price_failure(error):
                # 账号级：原价链仍被上游判成 0 元 → 走人工审批必 blocked。
                # 换出口/换指纹无用，立即停止同号整链重试，省代理与 CDK。
                #
                # 必须带 [ERROR] 前缀把原因写进日志：父进程靠子进程最后一行
                # 错误文案来生成用户可见报错，否则只会显示笼统的「子进程退出码 1」。
                log(
                    f"全部失败: {error}",
                    "[ERROR] ",
                )
                return 1
            else:
                risk_control = is_upstream_risk_control_error(error)
                if risk_control:
                    if record_risk_control(
                        error,
                        phase="provider",
                        proxy_seed=checkout_seed_used or checkout_proxy_used or provider_proxy,
                        fingerprint=fingerprint,
                    ):
                        return 1
                else:
                    if is_proxy_health_failure(error):
                        # Provider 阶段也是出口问题（TLS/超时/连接重置）：
                        # 允许下一轮换 Seed 重试，而不是直接结束这个账号。
                        transport_rotations_needed = True
                        log(
                            f"Provider 阶段命中出口网络层失败（{error[:120]}），"
                            "已记为可换出口重试",
                            "[WARN] ",
                        )
                    record_failure_by_stage(error, checkout_proxy_used, provider_proxy, promotion_proxy)
                log(f"Provider 失败: {error[:220]}", "[WARN] ")
                if is_approve_failure_error(error) and "approve blocked" in error:
                    approve_blocked_count += 1
                    log(f"approve blocked 计数: {approve_blocked_count}/{max_blocked}", "[WARN] ")
        finally:
            _log_context.prefix = previous_log_context
            if checkout_lease:
                checkout_lease.release()
                log("Seed 租约已释放")
                checkout_lease = None
            if checkout_seed_held:
                # provider/approve 阶段失败后，同一出口继续重试只会重复撞风控，
                # 把 Seed 移出候选，下一次提链换全新出口。
                _discard_held_seed("本轮提链失败")

        if approve_blocked_count >= max_blocked:
            log(
                "达到当前账号 approve blocked 上限，停止继续提交新提链；"
                "blocked 属于 OpenAI 0 元人工审批风控（官方 UI 同样提示 Payment was not approved），"
                "建议更换新账号或改走正价 UPI 路径，同号继续重试只会重复同一 dead path",
                "[WARN] ",
            )
            return 1
        log(f"第 {attempt}/{upi_retry} 次提链结束，未拿到最终 URL", "[WARN] ")

    log(f"全部失败: {last_error}", "[ERROR] ")
    if last_error == "UPI_PROXY_LEASE_BUSY" or lease_busy_hits:
        # 并发提链时每个 Seed 同时只能服务一个任务；候选全部被占用说明池子对当前
        # 并发太小（或都被上一轮租约占着），直接把可操作的结论写进日志。
        stats = lease_root_stats()
        log(
            f"本次共 {lease_busy_hits} 条 Seed 因被其它任务占用而跳过；"
            f"当前共存租约={stats['active']}（过期={stats['expired']}，目录={stats['root']}）；"
            f"候选池条数={len(proxy_seeds)}。并发任务较多或代理池偏小时会被互相占用，"
            "建议增加 Seed 数量、降低 UPI 并发，或把后台「API 批量提取数」调大。",
            "[WARN] ",
        )
    return 1


def main() -> int:
    """入口：所有失败路径都必须产出可读的 ``[ERROR]`` 行。

    以前 ``load_proxy_seeds()`` 等函数会直接 ``raise``，异常只写进 stderr 的
    traceback，父进程读到的 stdout 是**空的**；界面表现为「运行 0 秒、没有任何
    错误信息」，是最难排查的失败形态。这里把所有异常统一转成 ``[ERROR]`` 日志，
    保证任何启动期失败都有明确原因可读。
    """
    try:
        access_token, session_token = load_token()
        if not access_token:
            log("access_token 为空", "[ERROR] ")
            return 1

        # 必须在 load_proxy_seeds() 之前：过期 AT 100% 会在 checkout 第一步 401，
        # 提前返回可以完全不碰代理池（不取 Seed、不写健康度、不占并发槽）。
        expiry_error = precheck_access_token(access_token)
        if expiry_error:
            log(expiry_error, "[ERROR] ")
            return 1

        proxy_seeds = load_proxy_seeds()
        flow_mode = os.environ.get("UPI_FLOW_MODE", "single").strip().lower() or "single"
        if flow_mode != "single":
            log(f"UPI_FLOW_MODE={flow_mode} 已收敛为 strict single seed 链路", "[WARN] ")
        return run_single_link_mode(access_token, session_token, proxy_seeds)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        log("任务被手动中断", "[WARN] ")
        return 1
    except Exception as exc:  # noqa: BLE001 - 顶层兜底：保证失败必有可读原因
        detail = str(exc)
        # 常见的启动期致命错误直接按原文输出，避免再包一层导致文案走样。
        log(f"全部失败: {detail}", "[ERROR] ")
        return 1


if __name__ == "__main__":
    sys.exit(main())
