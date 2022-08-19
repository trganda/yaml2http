package com.github.trganda.functions;

import com.github.trganda.util.Util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public abstract class Functions {

    public static String randomInt(int min, int max) {
        int randomVal = (int)(Math.random() * (max - min) + min);
        return String.valueOf(randomVal);
    }

    public static String base64(String input) {
        return new String(Base64.getEncoder().encode(input.getBytes(StandardCharsets.UTF_8)));
    }

    public static String md5(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(input.getBytes(StandardCharsets.UTF_8));

        return new BigInteger(1, md.digest()).toString(16);
    }

    public static String md5(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(bytes);

        return new BigInteger(1, md.digest()).toString(16);
    }
}
