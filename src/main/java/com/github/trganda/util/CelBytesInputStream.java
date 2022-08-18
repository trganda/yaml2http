package com.github.trganda.util;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

/**
 * CelByteString was used to process the
 * <a>https://github.com/google/cel-spec/blob/master/doc/langdef.md#string-and-bytes-values</a> to
 * java byte array, and support convert to a String.
 */
public class CelBytesInputStream extends InputStream {

    private final ArrayList<Byte> buf;
    private final PeekInputStream in;

    /**
     * Start of the byte array, character 'b'.
     */
    final static byte CEL_BYTE_START = (byte)0x62;

    /**
     * Quote of the byte array, character '"'.
     */
    final static byte CEL_BYTE_QUOTE = (byte)0x22;

    /**
     * Escape of the byte array, character '\'.
     */
    final static byte CEL_BYTE_SLASH = (byte)0x5C;

    /**
     * Hex data of the byte array, upper character 'X'.
     */
    final static byte CEL_BYTE_UPHEX = (byte)0x58;

    /**
     * Hex of the byte array, lower character 'x'.
     */
    final static byte CEL_BYTE_LWHEX = (byte)0x78;

    final static byte CEL_ASCII_LOWA = (byte)0x61;

    final static byte CEL_OCTET_ZERO = (byte)0x30;

    final static byte CEL_OCTET_THREE = (byte)0x33;

    final static byte CEL_OCTET_SEVEN = (byte)0x37;

    public CelBytesInputStream(InputStream in) {
        buf = new ArrayList<>();
        this.in = new PeekInputStream(in);
    }

    public void process() throws IllegalArgumentException, IOException {

        byte cel = in.readByte();
        if (cel != CEL_BYTE_START) {
            throw new IOException();
        }
        cel = in.readByte();
        if (cel != CEL_BYTE_QUOTE) {
            throw new IOException();
        }

        buf.add(cel);
        while (in.available() > 0) {
            cel = in.readByte();
            switch (cel) {
                case CEL_BYTE_SLASH:
                    readHex();
                    break;
                case CEL_BYTE_QUOTE:
                    buf.add(cel);
                    break;
                default:
                    readAscii();
                    break;
            }
        }


    }

    public ArrayList<Byte> getBuf() {
        return buf;
    }

    private void readHex() throws IOException {
        byte cel = in.peekByte();
        if (cel == CEL_BYTE_UPHEX || cel == CEL_BYTE_LWHEX) {
            // hex value
            in.readByte();
            byte highHex = Util.toLowerCase(in.readByte());
            byte lowHex = Util.toLowerCase(in.readByte());
            if (!Util.isHexAscii(highHex) || !Util.isHexAscii(lowHex)) {
                throw new IOException();
            }

            highHex = Util.toHexValue(highHex);
            lowHex = Util.toHexValue(lowHex);

            byte hex = (byte) (lowHex + highHex << 4);
            buf.add(hex);
        } else {
            // octet value
            byte high = in.readHex();
            if (!Util.isDigit(high) && !(high >= CEL_OCTET_ZERO && high <= CEL_OCTET_THREE)) {
                throw new IOException();
            }
            byte mid = in.readHex();
            if (!Util.isDigit(mid) && !(high >= CEL_OCTET_ZERO && high <= CEL_OCTET_SEVEN)) {
                throw new IOException();
            }
            byte low = in.readHex();
            if (!Util.isDigit(low) && !(high >= CEL_OCTET_ZERO && high <= CEL_OCTET_SEVEN)) {
                throw new IOException();
            }
            byte hex = (byte) (low - CEL_OCTET_ZERO + (mid - CEL_OCTET_ZERO) << 3 + (high - CEL_OCTET_SEVEN) << 6);
            buf.add(hex);
        }
    }

    private void readAscii() throws IOException {
        byte cel = in.readByte();
        if (!Util.isAsciiByte(cel)) {
            throw new IOException();
        }
        buf.add(cel);
    }

    /**
     * Peeks at (but does not consume) and returns the next byte value in
     * the stream, or throws EOFException if end of stream/block data has
     * been reached.
     */
    byte peekByte() throws IOException {
        int val = in.peek();
        if (val < 0) {
            throw new EOFException();
        }
        return (byte) val;
    }

    @Override
    public int read() throws IOException {
        return in.read();
    }

    private static class PeekInputStream extends InputStream {

        /** underlying stream */
        private final InputStream in;
        /** peeked byte */
        private int peekb = -1;
        /** total bytes read from the stream */
        private long totalBytesRead = 0;

        /**
         * Creates new PeekInputStream on top of given underlying stream.
         */
        PeekInputStream(InputStream in) {
            this.in = in;
        }

        /**
         * Peeks at next byte value in stream.  Similar to read(), except
         * that it does not consume the read value.
         */
        int peek() throws IOException {
            if (peekb >= 0) {
                return peekb;
            }
            peekb = in.read();
            totalBytesRead += peekb >= 0 ? 1 : 0;
            return peekb;
        }

        /**
         * Peeks at (but does not consume) and returns the next byte value in
         * the stream, or throws EOFException if end of stream/block data has
         * been reached.
         */
        byte peekByte() throws IOException {
            int val = peek();
            if (val < 0) {
                throw new EOFException();
            }
            return (byte) val;
        }

        public int read() throws IOException {
            if (peekb >= 0) {
                int v = peekb;
                peekb = -1;
                return v;
            } else {
                int nbytes = in.read();
                totalBytesRead += nbytes >= 0 ? 1 : 0;
                return nbytes;
            }
        }

        public int read(byte[] b, int off, int len) throws IOException {
            int nbytes;
            if (len == 0) {
                return 0;
            } else if (peekb < 0) {
                nbytes = in.read(b, off, len);
                totalBytesRead += nbytes >= 0 ? nbytes : 0;
                return nbytes;
            } else {
                b[off++] = (byte) peekb;
                len--;
                peekb = -1;
                nbytes = in.read(b, off, len);
                totalBytesRead += nbytes >= 0 ? nbytes : 0;
                return (nbytes >= 0) ? (nbytes + 1) : 1;
            }
        }

        void readFully(byte[] b, int off, int len) throws IOException {
            int n = 0;
            while (n < len) {
                int count = read(b, off + n, len - n);
                if (count < 0) {
                    throw new EOFException();
                }
                n += count;
            }
        }

        public long skip(long n) throws IOException {
            if (n <= 0) {
                return 0;
            }
            int skipped = 0;
            if (peekb >= 0) {
                peekb = -1;
                skipped++;
                n--;
            }
            n = skipped + in.skip(n);
            totalBytesRead += n;
            return n;
        }

        public int available() throws IOException {
            return in.available() + ((peekb >= 0) ? 1 : 0);
        }

        public void close() throws IOException {
            in.close();
        }

        public long getBytesRead() {
            return totalBytesRead;
        }

        public final byte readByte() throws IOException {
            int ch = read();
            if (ch < 0)
                throw new EOFException();
            return (byte)(ch);
        }

        public final byte readHex() throws IOException {
            return 0x00;
        }
    }


}
