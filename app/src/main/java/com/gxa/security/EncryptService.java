package com.gxa.security;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class EncryptService extends Service {

    private static final String TAG = EncryptService.class.getSimpleName();
    private EncryptServiceImpl mServiceImpl;

    public EncryptService() {
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "onBind: " + intent);
        if (mServiceImpl == null) {
            mServiceImpl = new EncryptServiceImpl();
        }
        return mServiceImpl;
    }
}