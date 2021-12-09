package com.gxa.security;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


/**
 * @ProjectName: Security
 * @Package: com.gxa.security
 * @ClassName: AESKeystoreUtils
 * @Description: java类作用描述
 * @Author: JackOu
 * @CreateDate: 2021/8/27 16:32
 */
class AESKeystoreUtils {

    private static final String TAG = AESKeystoreUtils.class.getSimpleName();
    //  算法/模式/补码方式
    private static String TRANSFORMATION = "AES/GCM/NoPadding";
    private static byte[] encryptIv;
    private static AESKeystoreUtils mInstance;

    public static AESKeystoreUtils getInstance() {
        if (mInstance == null) {
            synchronized (AESKeystoreUtils.class) {
                if (mInstance == null) {
                    mInstance = new AESKeystoreUtils();
                }
            }
        }
        return mInstance;
    }

    /**
     * 创建秘钥
     */
    private void createKey(String alias) {
        //获取Android KeyGenerator的实例
        //设置使用KeyGenerator的生成的密钥加密算法是AES,在 AndroidKeyStore 中保存密钥/数据
        final KeyGenerator keyGenerator;
        AlgorithmParameterSpec spec = null;
        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            //使用KeyGenParameterSpec.Builder 创建KeyGenParameterSpec ,传递给KeyGenerators的init方法
            //KeyGenParameterSpec 是生成的密钥的参数
            //setBlockMode保证了只有指定的block模式下可以加密,解密数据,如果使用其它的block模式,将会被拒绝。
            //使用了“AES/GCM/NoPadding”变换算法,还需要设置KeyGenParameterSpec的padding类型
            //创建一个开始和结束时间,有效范围内的密钥对才会生成。
            Calendar start = new GregorianCalendar();
            Calendar end = new GregorianCalendar();
            end.add(Calendar.YEAR, 10);//往后加十年

            //todo 高于6.0才可以使用KeyGenParameterSpec 来生成秘钥，低版本呢？
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                spec = new KeyGenParameterSpec.Builder(alias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setCertificateNotBefore(start.getTime())
                        .setCertificateNotAfter(end.getTime())
                        .build();
            } else {
                Log.e(TAG, "system version is to tow.");
            }

            keyGenerator.init(spec);
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }


    public String encryptData(String needEncrypt, String alias) {
        if (!isHaveKeyStore(alias)) {
            createKey(alias);
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null);

            SecretKey secretKey = secretKeyEntry.getSecretKey();

            //KeyGenParameterSpecs中设置的block模式是KeyProperties.BLOCK_MODE_GCM,所以这里只能使用这个模式解密数据。
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            //ciphers initialization vector (IV)的引用,用于解密
            encryptIv = cipher.getIV();
            return Base64.encodeToString(cipher.doFinal(needEncrypt.getBytes()), Base64.NO_WRAP);
        } catch (IOException | KeyStoreException | CertificateException | InvalidKeyException
                | UnrecoverableEntryException | NoSuchPaddingException | BadPaddingException
                | IllegalBlockSizeException | NullPointerException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }

    public String decryptData(String needDecrypt, String alias) {
        if (!isHaveKeyStore(alias)) {
            createKey(alias);
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null);

            SecretKey secretKey = secretKeyEntry.getSecretKey();

            //KeyGenParameterSpecs中设置的block模式是KeyProperties.BLOCK_MODE_GCM,所以这里只能使用这个模式解密数据。
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            //需要为GCMParameterSpec 指定一个认证标签长度(可以是128、120、112、104、96这个例子中我们能使用最大的128),
            // 并且用到之前的加密过程中用到的IV。
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, encryptIv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            return new String(cipher.doFinal(Base64.decode(needDecrypt, Base64.NO_WRAP)));

        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IOException
                | CertificateException | NoSuchAlgorithmException | UnrecoverableEntryException
                | NoSuchPaddingException | KeyStoreException | BadPaddingException
                | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return "";
    }

    public void clearKeystore(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry(alias);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 是否创建过秘钥
     *
     * @return
     */
    private boolean isHaveKeyStore(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            KeyStore.Entry keyEntry = keyStore.getEntry(alias, null);
            if (null != keyEntry) {
                return true;
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException
                | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        return false;
    }
}
