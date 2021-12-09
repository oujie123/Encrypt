// IEncrypt.aidl
package com.gxa.security.client;

interface IEncrypt {

    // aes对称加密
    String aesEncrypt(in String alias, in String explainText);
    // aes对称解密
    String aesDecrypt(in String alias, in String cipherText);

    // rsa非对称加密
    String rsaEncrypt(in String alias, in String explainText);
    // rsa非对称解密
    String rsaDecrypt(in String alias, in String cipherText);

    // 获取随机字符串
    String getRandomString(in int num);
}