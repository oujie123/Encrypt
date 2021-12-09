package com.gxa.security;

import android.os.RemoteException;

import com.gxa.security.client.IEncrypt;

/**
 * @ClassName: EncryptServiceImpl
 * @Author: JackOu
 * @CreateDate: 2021/12/6 10:14
 */
class EncryptServiceImpl extends IEncrypt.Stub {

    @Override
    public String aesEncrypt(String alias, String explainText) throws RemoteException {
        return AESKeystoreUtils.getInstance().encryptData(explainText, alias);
    }

    @Override
    public String aesDecrypt(String alias, String cipherText) throws RemoteException {
        return AESKeystoreUtils.getInstance().decryptData(cipherText, alias);
    }

    @Override
    public String rsaEncrypt(String alias, String explainText) throws RemoteException {
        return EncryptSafeUtil.getInstance().encryptString(explainText, alias);
    }

    @Override
    public String rsaDecrypt(String alias, String cipherText) throws RemoteException {
        return EncryptSafeUtil.getInstance().decryptString(cipherText, alias);
    }

    @Override
    public String getRandomString(int num) throws RemoteException {
        return EncryptSafeUtil.getInstance().getRandomString(num);
    }
}
