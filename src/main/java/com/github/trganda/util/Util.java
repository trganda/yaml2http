package com.github.trganda.util;

import static com.github.trganda.util.CelBytesConstants.CEL_BYTE_LOW_A;
import static com.github.trganda.util.CelBytesConstants.CEL_BYTE_ZERO;

public class Util {

    public static String hex2Unicode(String expression) {
        int idx = 0;
        while (idx < expression.length()) {
            char cur = expression.charAt(idx);
            if (cur == '\\' && (expression.length() - idx - 1) > 2 && (expression.charAt(idx+1) == 'x' || expression.charAt(idx+1) == 'X')) {
                char a = (char) ((int)Integer.decode("0x" + expression.substring(idx + 2, idx + 4)));
                expression = expression.substring(0, idx) + a + expression.substring(idx+4);
            }
            idx++;
        }

        return expression;
    }

    public static byte[] getBytes(String expression) {
        char[] buffer = expression.toCharArray();
        byte[] bytes = new byte[buffer.length];

        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte)(buffer[i] & 0x00FF);
        }

        return bytes;
    }

    public static String bytes2String(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append((char)(b & 0x00FF));
        }
        return sb.toString();
    }


    public static boolean isAsciiByte(byte ascii) {
        return ascii >= 0x00;
    }

    public static boolean isDigit(byte ascii) {
        return (ascii >= 0x30 && ascii <= 0x39);
    }

    public static boolean isLetter(byte ascii) {
        return isUpperCase(ascii) || isLowerCase(ascii);
    }

    public static boolean isHexAscii(byte ascii) {
        ascii = Util.toLowerCase(ascii);
        return Util.isDigit(ascii) || (Util.isLowerCase(ascii) && ascii <= 0x66);
    }

    public static byte toHexValue(byte ascii) {
        if (Util.isHexAscii(ascii)) {
            ascii = Util.toLowerCase(ascii);
            if (Util.isDigit(ascii)) {
                ascii = (byte) (ascii - CEL_BYTE_ZERO);
            } else {
                ascii = (byte) (ascii - CEL_BYTE_LOW_A + 10);
            }
            return ascii;
        }
        return ascii;
    }

    public static boolean isUpperCase(byte ascii) {
        return (ascii >= 0x41 && ascii <= 0x5A);
    }

    public static boolean isLowerCase(byte ascii) {
        return (ascii >= 0x61 && ascii <= 0x7A);
    }

    public static byte toUpperCase(byte ascii) {
        if (isUpperCase(ascii)) {
            return ascii;
        } else if (isLowerCase(ascii)) {
            return (byte)(ascii - 0x20);
        }

        return ascii;
    }

    public static byte toLowerCase(byte ascii) {
        if (isLowerCase(ascii)) {
            return ascii;
        } else if (isUpperCase(ascii)) {
            return (byte)(ascii + 0x20);
        }

        return ascii;
    }

    public static char byte2char(byte ascii) throws IllegalArgumentException {
        if (isLetter(ascii)) {
            return (char) ascii;
        } else {
            throw new IllegalArgumentException("The arg was not a valid ascii byte.");
        }
    }

}
