package com.zorro.jni;

import android.os.Bundle;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

import com.zorro.jni.util.EncryptUtils;
import com.zorro.jni.databinding.ActivityMainBinding;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public class MainActivity extends AppCompatActivity {


    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        // Example of a call to a native method
        binding.key.setText("加解密秘钥:\n" + EncryptUtils.publicKeyStringFromJNI());
        AtomicReference<String> jiami = new AtomicReference<>();
        binding.btnEncrypt.setOnClickListener(v -> {
            jiami.set(EncryptUtils.encrypt(Objects.requireNonNull(binding.input.getText()).toString()));
            binding.encryptText.setText("加密结果:\n" + jiami);
            Log.e("code", jiami.get());
        });
        binding.btnDecrypt.setOnClickListener(v -> {
            String jiemi = EncryptUtils.decrypt(jiami.get());
            binding.decryptText.setText("解密结果:\n" + jiemi);
            Log.e("code", jiemi);
        });
    }
}