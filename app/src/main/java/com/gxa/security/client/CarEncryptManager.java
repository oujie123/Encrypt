package com.gxa.security.client;

import android.content.Context;

/**
 * @ClassName: CarEncryptManager
 * @Author: JackOu
 * @CreateDate: 2021/12/6 12:53
 */
public abstract class CarEncryptManager {

    protected static final String PACKAGE_NAME = "com.gxa.security";
    protected static final String SERVICE_NAME = "com.gxa.security.EncryptService";

    private static CarEncryptManager mInstance;

    public static CarEncryptManager getInstance() {
        if (mInstance == null) {
            synchronized (CarEncryptManager.class) {
                if (mInstance == null) {
                    mInstance = new CarEncryptManagerImpl();
                }
            }
        }
        return mInstance;
    }

    // 初始化
    public abstract int init(Context context);

    // aes对称加密
    public abstract String aesEncrypt(String alias, String explainText);

    // aes对称解密
    public abstract String aesDecrypt(String alias, String cipherText);

    // rsa非对称加密
    public abstract String rsaEncrypt(String alias, String explainText);

    // rsa非对称解密
    public abstract String rsaDecrypt(String alias, String cipherText);

    // 获取随机字符串
    public abstract String getRandomString(int num);
}
