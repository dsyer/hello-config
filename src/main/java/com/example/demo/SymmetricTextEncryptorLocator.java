package com.example.demo;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.config.server.encryption.TextEncryptorLocator;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("secrets")
public class SymmetricTextEncryptorLocator implements TextEncryptorLocator {

    private final static String KEY = "key";
    private Map<String, TextEncryptor> encryptors = new HashMap<>();
    private TextEncryptor defaultEncryptor;
    private String defaultAlias = "default";
    private String salt = "deadbeef";

    public SymmetricTextEncryptorLocator(final TextEncryptor defaultEncryptor) {
        this.defaultEncryptor = defaultEncryptor;
    }

    @Override
    public TextEncryptor locate(Map<String, String> keys) {
        String alias = keys.containsKey(KEY) ? keys.get(KEY) : this.defaultAlias;
        if (alias.equals(this.defaultAlias) || !encryptors.containsKey(alias) ) {
            return this.defaultEncryptor;
        } else {
            return encryptors.get(alias);
        }
    }

    public void setKeys(Map<String, String> keys) {
        for (String key : keys.keySet()) {
            this.encryptors.put(key, Encryptors.delux(keys.get(key), this.salt));
        }
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
