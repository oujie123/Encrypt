package com.gxa.security;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.gxa.security.client.CarEncryptManager;

/**
 * https://github.com/icastillejogomez/OpenSSL-Java-API
 */
public class MainActivity extends Activity implements View.OnClickListener {

    private static final String TAG = MainActivity.class.getSimpleName();
    private static final String rsaAlias = "com.gxa.security.rsa";
    private static final String aesAlias = "com.gxa.security.aes";
    private static final String SP_RSA_CIPHER_TEXT = "rsa_cipher_text";
    private static final String SP_AES_CIPHER_TEXT = "aes_cipher_text";
    private static String rsaExplainText = "hello world";
    private static String rsaCipherText;
    private static String aesExplainText = "hello world";
    private static String aesCipherText;
    private Button rsaEncrypt;
    private Button rsaDecrypt;
    private Button aesEncrypt;
    private Button aesDecrypt;
    private Button genText;
    private TextView text;
    private SharedPreferences sp;
    private SharedPreferences.Editor editor;

    private CarEncryptManager mManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        rsaEncrypt = findViewById(R.id.rsa_encrypt);
        rsaDecrypt = findViewById(R.id.rsa_decrypt);
        aesEncrypt = findViewById(R.id.aes_encrypt);
        aesDecrypt = findViewById(R.id.aes_decrypt);
        genText = findViewById(R.id.random_text);
        text = findViewById(R.id.textView);

        rsaEncrypt.setOnClickListener(this);
        rsaDecrypt.setOnClickListener(this);
        genText.setOnClickListener(this);
        aesEncrypt.setOnClickListener(this);
        aesDecrypt.setOnClickListener(this);
        text.setText(rsaExplainText);

        sp = getSharedPreferences("jack", Context.MODE_PRIVATE);
        rsaCipherText = sp.getString(SP_RSA_CIPHER_TEXT, "default text");
        aesCipherText = sp.getString(SP_AES_CIPHER_TEXT, "default text");
        text.setText(rsaCipherText);

        mManager = CarEncryptManager.getInstance();
        mManager.init(this);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.rsa_encrypt:  // rsa encrypt
                rsaCipherText = mManager.rsaEncrypt(rsaAlias, rsaExplainText);
                editor = sp.edit();
                editor.putString(SP_RSA_CIPHER_TEXT, rsaCipherText);
                editor.apply();
                text.setText(rsaCipherText);
                break;
            case R.id.rsa_decrypt: // rsa decrypt
                rsaExplainText = mManager.rsaDecrypt(rsaAlias, rsaCipherText);
                text.setText(rsaExplainText);
                break;
            case R.id.random_text: // gen random text
                rsaExplainText = mManager.getRandomString(100);
                aesExplainText = rsaExplainText;
                Log.d(TAG, "random text = " + aesExplainText);
                text.setText(rsaExplainText);
                break;
            case R.id.aes_encrypt: //aes encrypt
                aesCipherText = mManager.aesEncrypt(aesAlias, aesExplainText);
                editor = sp.edit();
                editor.putString(SP_AES_CIPHER_TEXT, aesCipherText);
                editor.apply();
                Log.d(TAG, "aesCipherText = " + aesCipherText + " \n" + aesCipherText.length());
                text.setText(aesCipherText);
                break;
            case R.id.aes_decrypt: // aes decrypt
                aesExplainText = mManager.aesDecrypt(aesAlias, aesCipherText);
                Log.d(TAG, "aesExplainText = " + aesExplainText);
                text.setText(aesExplainText);
                break;
            default:
                break;
        }
    }
}