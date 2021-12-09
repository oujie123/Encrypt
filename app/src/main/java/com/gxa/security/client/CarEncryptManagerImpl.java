package com.gxa.security.client;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;

import com.gxa.security.Constants;

/**
 * @ClassName: EncryptManager
 * @Author: JackOu
 * @CreateDate: 2021/12/6 10:17
 */
public class CarEncryptManagerImpl extends CarEncryptManager {

    private static final String TAG = CarEncryptManagerImpl.class.getSimpleName();
    private IEncrypt mService;

    @Override
    public int init(Context context) {
        if (context == null) return -1;
        bindService(context);
        return 0;
    }

    @Override
    public String aesEncrypt(String alias, String explainText) {
        if (checkStringIsEmpty(alias, explainText)) return null;
        String ret = "";
        Log.d(TAG, "aesEncrypt: alias=" + alias + ", explainText=" + explainText);
        if (mService != null) {
            try {
                ret = mService.aesEncrypt(alias, explainText);
            } catch (RemoteException e) {
                Log.e(TAG, "aesEncrypt: " + e.getMessage());
            }
        } else {
            Log.e(TAG, "aesEncrypt: IEncrypt Service is not available.");
            ret = null;
        }
        return ret;
    }

    @Override
    public String aesDecrypt(String alias, String cipherText) {
        if (checkStringIsEmpty(alias, cipherText)) return null;
        String ret = "";
        Log.d(TAG, "aesDecrypt: alias=" + alias + ", cipherText=" + cipherText);
        if (mService != null) {
            try {
                ret = mService.aesDecrypt(alias, cipherText);
            } catch (RemoteException e) {
                Log.e(TAG, "aesDecrypt: " + e.getMessage());
            }
        } else {
            Log.e(TAG, "aesDecrypt: IEncrypt Service is not available.");
            ret = null;
        }
        return ret;
    }

    @Override
    public String rsaEncrypt(String alias, String explainText) {
        if (checkStringIsEmpty(alias, explainText)) return null;
        String ret = "";
        Log.d(TAG, "rsaEncrypt: alias=" + alias + ", explainText=" + explainText);
        if (mService != null) {
            try {
                ret = mService.rsaEncrypt(alias, explainText);
            } catch (RemoteException e) {
                Log.e(TAG, "rsaEncrypt: " + e.getMessage());
            }
        } else {
            Log.e(TAG, "rsaEncrypt: IEncrypt Service is not available.");
            ret = null;
        }
        return ret;
    }

    @Override
    public String rsaDecrypt(String alias, String cipherText) {
        if (checkStringIsEmpty(alias, cipherText)) return null;
        String ret = "";
        Log.d(TAG, "rsaDecrypt: alias=" + alias + ", cipherText=" + cipherText);
        if (mService != null) {
            try {
                ret = mService.rsaDecrypt(alias, cipherText);
            } catch (RemoteException e) {
                Log.e(TAG, "rsaDecrypt: " + e.getMessage());
            }
        } else {
            Log.e(TAG, "rsaDecrypt: IEncrypt Service is not available.");
            ret = null;
        }
        return ret;
    }

    @Override
    public String getRandomString(int num) {
        if (num <= 0) return null;
        String ret = "";
        Log.d(TAG, "getRandomString: num=" + num);
        if (mService != null) {
            try {
                ret = mService.getRandomString(num);
            } catch (RemoteException e) {
                Log.d(TAG, "getRandomString: " + e.getMessage());
            }
        } else {
            Log.d(TAG, "getRandomString: IEncrypt Service is not available.");
            ret = null;
        }
        return ret;
    }

    private ServiceConnection mConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            Log.d(TAG, "onServiceConnected: className=" + name + ", service=" + service);
            mService = IEncrypt.Stub.asInterface(service);
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.d(TAG, "onServiceDisconnected: className=" + name);
            mService = null;
        }
    };

    private void bindService(Context context) {
        Intent intent = new Intent();
        intent.setComponent(new ComponentName(Constants.PACKAGE_NAME, Constants.SERVICE_NAME));
        context.bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
    }

    private boolean checkStringIsEmpty(String... strings) {
        for (String s : strings) {
            if (TextUtils.isEmpty(s)) return true;
        }
        return false;
    }
}
