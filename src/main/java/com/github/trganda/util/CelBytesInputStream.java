package com.github.trganda.util;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import static com.github.trganda.util.CelBytesConstants.*;

/**
 * CelByteString was used to process the
 * <a>https://github.com/google/cel-spec/blob/master/doc/langdef.md#string-and-bytes-values</a> to
 * java byte array, and support convert to a String.
 */
public class CelBytesInputStream extends InputStream {

    private final ByteArrayOutputStream buf;
    private final PeekInputStream in;

    public CelBytesInputStream(InputStream in) {
        buf = new ByteArrayOutputStream();
        this.in = new PeekInputStream(in);
    }

    /**
     * Read the cel bytes value from underling InputStream.
     * @throws IOException
     */
    public void readCelBytes() throws IOException {

        // start character 'b'
        byte cel = in.readByte();
        if (cel != CEL_BYTE_START) {
            throw new IOException();
        }
        // the first quote '"'
        cel = in.readByte();
        if (cel != CEL_BYTE_QUOTE && cel != CEL_BYTE_SINGLE_QUOTE) {
            throw new IOException();
        }

        boolean ended = false;
        while (in.available() > 0 && !ended) {
            cel = in.peekByte();
            switch (cel) {
                case CEL_BYTE_SLASH:
                    readSlash();
                    break;
                case CEL_BYTE_QUOTE:
                case CEL_BYTE_SINGLE_QUOTE:
                    in.readByte();
                    ended = true;
                    break;
                default:
                    readAscii();
                    break;
            }
        }
    }

    /**
     * Get the underling byte array.
     * @return underling read bytes.
     */
    public byte[] getByteBuf() {
        return buf.toByteArray();
    }

    /**
     * Get a String format of underling read byte array.
     * @return String format byte array.
     */
    public String getBufString() {
        byte[] bytes = getByteBuf();
        StringBuilder sb = new StringBuilder();

        sb.append("new byte[]{");
        for (byte b : bytes) {
            sb.append(b).append(",");
        }
        sb.deleteCharAt(sb.lastIndexOf(","));
        sb.append("}");

        return sb.toString();
    }

    /**
     * Read a hex value with the format \xaa
     * @throws IOException
     */
    private void readHex() throws IOException {
        // hex value
        in.readByte();
        byte highHex = Util.toLowerCase(in.readByte());
        byte lowHex = Util.toLowerCase(in.readByte());
        if (!Util.isHexAscii(highHex) || !Util.isHexAscii(lowHex)) {
            throw new IOException();
        }

        highHex = Util.toHexValue(highHex);
        lowHex = Util.toHexValue(lowHex);

        byte hex = (byte) (lowHex + (highHex << 4));
        buf.write(hex);
    }

    /**
     * Read an octet value wiht the format \000
     * @throws IOException
     */
    private void readOctet() throws IOException {
        // octet value
        byte high = in.readByte();
        if (!Util.isDigit(high) || !(high >= CEL_BYTE_ZERO && high <= CEL_BYTE_THREE)) {
            throw new IOException();
        }
        byte mid = in.readByte();
        if (!Util.isDigit(mid) || !(mid >= CEL_BYTE_ZERO && mid <= CEL_BYTE_SEVEN)) {
            throw new IOException();
        }
        byte low = in.readByte();
        if (!Util.isDigit(low) || !(low >= CEL_BYTE_ZERO && low <= CEL_BYTE_SEVEN)) {
            throw new IOException();
        }
        byte hex = (byte) (low - CEL_BYTE_ZERO + ((mid - CEL_BYTE_ZERO) << 3) + ((high - CEL_BYTE_SEVEN) << 6));
        buf.write(hex);
    }

    /**
     * Read an escape value that was start with \
     * @throws IOException
     */
    private void readSlash() throws IOException {
        in.readByte();
        byte cel = in.peekByte();
        switch (cel) {
            case CEL_BYTE_UP_X:
            case CEL_BYTE_LOW_X:
                readHex();
                break;
            case CEL_BYTE_QUOTE:
                in.readByte();
                buf.write(CEL_BYTE_QUOTE);
                break;
            case CEL_BYTE_QUESTION:
                in.readByte();
                buf.write(CEL_BYTE_QUESTION);
                break;
            case CEL_BYTE_SINGLE_QUOTE:
                in.readByte();
                buf.write(CEL_BYTE_SINGLE_QUOTE);
                break;
            case CEL_BYTE_BACKTICK:
                in.readByte();
                buf.write(CEL_BYTE_BACKTICK);
                break;
            case CEL_BYTE_SLASH:
                in.readByte();
                buf.write(CEL_BYTE_SLASH);
                break;
            case CEL_BYTE_LOW_A:
                in.readByte();
                buf.write(0x07);
                break;
            case CEL_BYTE_LOW_B:
                in.readByte();
                buf.write(0x08);
                break;
            case CEL_BYTE_LOW_R:
                in.readByte();
                buf.write(0x0d);
                break;
            case CEL_BYTE_LOW_F:
                in.readByte();
                buf.write(0x0c);
                break;
            case CEL_BYTE_LOW_N:
                in.readByte();
                buf.write(0x0a);
                break;
            case CEL_BYTE_T:
                in.readByte();
                buf.write(0x09);
                break;
            case CEL_BYTE_V:
                in.readByte();
                buf.write(0x0b);
                break;
            default:
                readOctet();
                break;
        }

    }

    /**
     * Read a ascii value between 0x00-0x7F
     * @throws IOException
     */
    private void readAscii() throws IOException {
        byte cel = in.readByte();
        if (!Util.isAsciiByte(cel)) {
            throw new IOException();
        }
        buf.write(cel);
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

    }

}
