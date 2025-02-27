# -*- coding: utf-8 -*-
"""
@Project Name: WebShellDecryptor
@Name: PhpEvalXorBase64.py
@Auth: C1ph3rX13
@Date: 2025/2/27-15:25
@Desc: Godzilla PHP_EVAL_XOR_BASE64 Decryptor
@Python Version: 3.11
"""

import base64
import zlib
from urllib.parse import unquote
from urllib.parse import unquote_to_bytes


def request_decode(encrypted_str: str) -> bytes:
    """
    PHP加密逆向操作：base64_decode(strrev(urldecode($data)))
    对应 pass(密码)=“加密内容” 的解密流程

    处理流程：
    原始数据 → URL编码 → 字符串反转 → Base64编码 → 传输
    解密流程：
    接收数据 → URL解码 → 字符串反转 → Base64解码 → 原始数据
    """
    # Step 1: URL解码
    url_decoded = unquote(encrypted_str)

    # Step 2: 字符串反转（PHP的strrev等效操作）
    reversed_str = url_decoded[::-1]

    # Step 3: Base64解码
    return base64.b64decode(reversed_str)


def request_decrypt(encrypted_data: str, key: str) -> bytes:
    """
    Godzilla PHP加密逆向实现（对应PHP的encode函数逻辑）
    对应 key=“加密内容” 的解密流程
    <?php
        function encode($D, $K) {
            for ($i = 0; $i < strlen($D); $i++) {
                $c = $K[$i + 1 & 15];
                $D[$i] = $D[$i] ^ $c;
            }
            return $D;
        }
        $data = '加密内容';
        $key = '3c6e0b8a9c15224a';
        $payload = encode(base64_decode(urldecode($data)), $key);
        print($payload);
    ?>

    :param encrypted_data: 经过URL编码和Base64编码的加密数据
    :param key: 16字节密钥字符串（如'3c6e0b8a9c15224a'）
    :return: 解密后的原始字符串
    """
    url_decoded = unquote_to_bytes(encrypted_data)

    try:
        b64_decoded = base64.b64decode(url_decoded, validate=True)
    except Exception as e:
        raise ValueError(f"Base64解码失败: {str(e)}")

    # 4. XOR解密（修复PHP的密钥循环逻辑）
    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 16:
        raise ValueError("密钥必须为16字节")

    decrypted = bytearray()
    for i, b in enumerate(b64_decoded):
        key_pos = (i + 1) % 16  # PHP的循环逻辑：$i+1 & 0xF
        decrypted.append(b ^ key_bytes[key_pos])

    return decrypted


def response_decrypt(encrypted_str: str, key: str) -> str:
    """
    Godzilla PHP_EVAL_XOR_BASE64 response 解密
    流程：URL解码 → Base64解码 → XOR解密 → Gzip解压
    """
    # 1. 提取有效数据部分（根据实际数据格式调整）
    encrypted_data = encrypted_str[16:-16]  # 需要根据实际数据格式确认切片位置

    decrypted = request_decrypt(encrypted_data, key)

    # 5. Gzip解压（自动处理头信息）
    try:
        # 尝试自动检测GZIP头
        decompressed = zlib.decompress(decrypted, zlib.MAX_WBITS | 32)
    except zlib.error:
        try:
            # 回退到原始DEFLATE数据
            decompressed = zlib.decompress(decrypted, -zlib.MAX_WBITS)
        except zlib.error as e:
            print("[调试信息] 解压失败数据头部：", decrypted[:8].hex())
            raise ValueError("解压失败，请检查解密结果") from e

    # 6. 去除Godzilla的填充数据（16字节头尾）
    if len(decompressed) < 32:
        return decompressed.decode('utf-8', errors='replace')
    return decompressed[16:-16].decode('utf-8', errors='replace')


# CyberChef 密钥预处理代码
def CyberChef_key(php_key: str) -> str:
    """
    Godzilla PHP_EVAL_XOR_BASE64 加密逆向实现
    XOR 密钥循环左移1位

    :param php_key: key → md5
    :return: CyberChef key (UTF-8)
    """
    if len(php_key) != 16:
        raise ValueError("密钥必须为16字节")
    return php_key[1:] + php_key[0]


# 使用示例
if __name__ == "__main__":
    # request decode / pass decode
    # 解码数据为密码的内容 pass="解码内容"
    # request_data = ''
    # result = request_decode(request_data)
    # print("解密结果:")
    # print(result.decode('utf-8'))

    # request decode / key decode
    # 解密数据为密钥的内容 key="解码内容"
    # request_data = ''
    # secret_key = '3c6e0b8a9c15224a'  # 默认密钥(key)的md5前16位
    # result = request_decrypt(request_data, secret_key)
    # print("解密结果:")
    # print(f"[*] 原始字节: {repr(result.decode('utf-8', errors='replace'))}")  # 显示原始控制字符
    # # 先处理字节数据，数据解密后存在回车符，可能会截断数据
    # cleaned = result.translate(bytes.maketrans(b'', b''), delete=b'\r')
    # # 再解码输出
    # print(f"[*] UTF-8 编码: {cleaned.decode('utf-8', errors='replace')}")

    # response decrypt
    response_date = ''
    secret_key = '3c6e0b8a9c15224a'  # 默认密钥(key)的md5前16位
    result = response_decrypt(response_date, secret_key)
    print('[*] 格式化解密')
    print(result)

    # CyberChef 密钥预处理示例
    # original_key = "3c6e0b8a9c15224a"
    # adjusted_key = CyberChef_key(original_key)  # 用于CyberChef的密钥
    # print(f'CyberChef Key: {adjusted_key}') # 3c6e0b8a9c15224a 偏移后 c6e0b8a9c15224a3
