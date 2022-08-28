package com.github.trganda.functions;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public abstract class Functions {

    public static String randomInt(int min, int max) {
        int randomVal = (int)(Math.random() * (max - min) + min);
        return String.valueOf(randomVal);
    }

    public static String base64(String input) {
        return new String(Base64.getEncoder().encode(input.getBytes(StandardCharsets.UTF_8)));
    }

    public static String base64(byte[] input) {
        return new String(Base64.getEncoder().encode(input));
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

    public static String base64Decode(String input) {
        return new String(Base64.getDecoder().decode(input.getBytes(StandardCharsets.UTF_8)));
    }

    public static String base64Decode(byte[] bytes) {
        return new String(Base64.getDecoder().decode(bytes));
    }

    public static String urlencode(String input) throws UnsupportedEncodingException {
        return URLEncoder.encode(input, "UTF-8");
    }

    public static String urlencode(byte[] bytes) throws UnsupportedEncodingException {
        return URLEncoder.encode(new String(bytes, StandardCharsets.UTF_8), "UTF-8");
    }

    public static String urldecode(String input) throws UnsupportedEncodingException {
        return URLDecoder.decode(input, "UTF-8");
    }

    public static String urldecode(byte[] bytes) throws UnsupportedEncodingException {
        return URLDecoder.decode(new String(bytes, StandardCharsets.UTF_8), "UTF-8");
    }

    public static byte[] desdecode(byte[] bytes, String keyStr) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeySpecException, InvalidAlgorithmParameterException {
        byte[] keyByte = keyStr.getBytes();
        DESKeySpec dks1 = new DESKeySpec(keyByte);
        SecretKey key = SecretKeyFactory.getInstance("DES").generateSecret(dks1);
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(bytes);
    }

     public static String substr(String input, int start, int length) {
        return input.substring(start, start + length);
     }

}
