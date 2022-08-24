package com.github.trganda.util;

import java.util.List;

import static com.github.trganda.util.CelBytesConstants.*;

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
        ascii = toLowerCase(ascii);
        return isDigit(ascii) || (isLowerCase(ascii) && ascii <= 0x66);
    }

    public static boolean isPrintable(byte ascii) {
        return ascii >= 0x20 && ascii <= 0x7E;
    }

    /**
     * calc the ascii value to hex value, 0x61 (ascii 'a') to 0x0a (number)
     * @param ascii input ascii
     * @return byte number
     */
    public static byte toHexValue(byte ascii) {
        if (isHexAscii(ascii)) {
            ascii = toLowerCase(ascii);
            if (isDigit(ascii)) {
                ascii = (byte) (ascii - CEL_BYTE_ZERO);
            } else {
                ascii = (byte) (ascii - CEL_BYTE_LOW_A + 10);
            }
            return ascii;
        }
        return ascii;
    }

    /**
     * Split the high 4 bit to ascii value and low 4 bit to another ascii value, 0x00 -> "00"
     * @param hex input hex
     * @return converted String.
     */
    public static String toHexString(byte hex) {
        byte low = (byte)(hex & 0x0F);
        byte high = (byte)((hex & 0xF0) >> 4);

        String ret = "";

        ret += String.valueOf(toChar(high));
        ret += String.valueOf(toChar(low));

        return ret;
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

    /**
     * hex byte to char, like 0x0a (hex number) -> 0x61 (ascii value)
     * @param hex hex number
     * @return ascii value
     */
    public static char toChar(byte hex) throws IllegalArgumentException {
        if (!(0 <= hex && hex <= 0x0F))
            throw new IllegalArgumentException("No expect hex value" + hex);

        if (hex < 0x0a) {
            return (char)(hex + CEL_BYTE_ZERO);
        } else {
            return (char)(hex - 0x0a + CEL_BYTE_LOW_A);
        }
    }

    public static void addAll(List<Byte> list, byte[] bytes) {
        for (byte bt : bytes) {
            list.add(bt);
        }
    }

    /**
     * Convert a byte array to cel bytes value
     * @param bytes byte array need to be convert
     * @return a format string like b"...."
     */
    public static String toBytesValue(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append("b\"");

        for (byte bt : bytes) {
            if (isLetter(bt) || isDigit(bt)) {
                sb.append((char) bt);
            } else {
                sb.append("\\x");
                sb.append(toHexString(bt));
            }
        }
        sb.append("\"");

        return sb.toString();
    }

}
