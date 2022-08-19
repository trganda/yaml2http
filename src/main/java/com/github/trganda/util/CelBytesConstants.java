package com.github.trganda.util;

public interface CelBytesConstants {

    /**
     * Start of the byte array, character 'b'.
     */
    final static byte CEL_BYTE_START = (byte)0x62;

    /**
     * Quote of the byte array, character '"'.
     */
    final static byte CEL_BYTE_QUOTE = (byte)0x22;

    /**
     * Escape character '\'.
     */
    final static byte CEL_BYTE_SLASH = (byte)0x5C;

    /**
     * Ascii '?'.
     */
    final static byte CEL_BYTE_QUESTION = (byte)0x3F;

    /**
     * Ascii '''.
     */
    final static byte CEL_BYTE_SINGLE_QUOTE = (byte)0x27;

    /**
     * Ascii '`'.
     */
    final static byte CEL_BYTE_BACKTICK = (byte)0x60;

    /**
     * Ascii 'f', form feed.
     */
    final static byte CEL_BYTE_LOW_F = (byte)0x66;

    /**
     * Ascii 'n', line feed.
     */
    final static byte CEL_BYTE_LOW_N = (byte)0x6E;

    /**
     * Ascii 't', horizontal tab.
     */
    final static byte CEL_BYTE_T = (byte)0x74;

    /**
     * Ascii 'v', vertical tab.
     */
    final static byte CEL_BYTE_V = (byte)0x76;

    /**
     * Ascii 'X'.
     */
    final static byte CEL_BYTE_UP_X = (byte)0x58;

    /**
     * Ascii 'x'.
     */
    final static byte CEL_BYTE_LOW_X = (byte)0x78;

    /**
     * Ascii 'a', bell.
     */
    final static byte CEL_BYTE_LOW_A = (byte)0x61;

    /**
     * Ascii 'b', backspace.
     */
    final static byte CEL_BYTE_LOW_B = (byte)0x62;

    /**
     * Ascii 'r', carriage return.
     */
    final static byte CEL_BYTE_LOW_R = (byte)0x72;

    /**
     * Ascii '0'.
     */
    final static byte CEL_BYTE_ZERO = (byte)0x30;

    /**
     * Ascii '3'.
     */
    final static byte CEL_BYTE_THREE = (byte)0x33;

    /**
     * Ascii '7'.
     */
    final static byte CEL_BYTE_SEVEN = (byte)0x37;

    final static byte[] CEL_BYTE_MAGIC = new byte[]{(byte) 0xac, (byte) 0xed, (byte) 0x40, (byte) 0x54};
}
