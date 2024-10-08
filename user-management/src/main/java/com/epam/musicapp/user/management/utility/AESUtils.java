package com.epam.musicapp.user.management.utility;

import com.epam.musicapp.user.management.exception.DecryptionException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;

import static com.epam.musicapp.user.management.constants.UserConstants.*;

public class AESUtils {

    private AESUtils() {
    }

    private static final String SECRET_KEY = "secret key 12356";

    public static String decrypt(String encryptedData) {
        try {
            SecretKeySpec sKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, sKey);

            byte[] decode = Base64.getDecoder().decode(encryptedData);
            byte[] original = cipher.doFinal(decode);

            return new String(original);
        } catch (Exception e) {
            throw new DecryptionException(DECRYPTION_ERROR + e.getMessage(), e);
        }
    }
}