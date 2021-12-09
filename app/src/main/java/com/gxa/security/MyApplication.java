package com.gxa.security;

import android.app.Application;
import android.content.ComponentName;
import android.content.Intent;

/**
 * @ClassName: MyApplication
 * @Author: JackOu
 * @CreateDate: 2021/12/6 13:51
 */
public class MyApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        startService(new Intent().setComponent(new ComponentName(Constants.PACKAGE_NAME, Constants.SERVICE_NAME)));
    }

}
