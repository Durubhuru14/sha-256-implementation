package sha256implementation;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * SHA-256 implementation based on NIST FIPS 180-4 specification.
 *
 * SHA-256 processes messages in 512-bit blocks and produces a 256-bit hash.
 * The algorithm uses:
 * - 64-word message schedule (32-bit words)
 * - 8 working variables (a, b, c, d, e, f, g, h)
 * - 8-word hash value (H0 to H7)
 * <p>
 * <b>Link to the official NIST FIPS 180-4 Doc :
 * {@link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf}
 * </b>
 * </p>
 */
public class SHA256 {

    /**
     * Initial hash values (H0..H7).
     *
     * These are the first 32 bits of the fractional parts of
     * the square roots of the first 8 prime numbers
     * (2, 3, 5, 7, 11, 13, 17, 19).
     */
    private static final int[] INITIAL_HASH = {
            0x6a09e667, // H0
            0xbb67ae85, // H1
            0x3c6ef372, // H2
            0xa54ff53a, // H3
            0x510e527f, // H4
            0x9b05688c, // H5
            0x1f83d9ab, // H6
            0x5be0cd19 // H7
    };

    /**
     * Round constants (K0..K63).
     *
     * These are the first 32 bits of the fractional parts of
     * the cube roots of the first 64 prime numbers.
     */
    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private int[] hash;

    public SHA256() {
        // Initialize hash with initial hash values
        hash = INITIAL_HASH.clone();
    }

    /**
     * Right rotate (circular right shift) operation
     *
     * Formula: ROTR^n(x) = (x >> n) | (x << (w - n))
     * where w is the word size (32 bits for SHA-256)
     *
     * @param x The value to rotate
     * @param n Number of bits to rotate
     * @return The rotated value
     */
    private int rightRotate(int x, int n) {
        return (x >>> n) | (x << (32 - n));
    }

    /**
     * Right shift operation
     *
     * Formula: SHR^n(x) = x >> n
     *
     * @param x The value to shift
     * @param n Number of bits to shift
     * @return The shifted value
     */
    private int rightShift(int x, int n) {
        return x >>> n;
    }

    /**
     * Choice function
     *
     * Formula: Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)
     *
     * @param x First input
     * @param y Second input
     * @param z Third input
     * @return Result of the choice function
     */
    private int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    /**
     * Majority function
     *
     * Formula: Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
     *
     * @param x First input
     * @param y Second input
     * @param z Third input
     * @return Result of the majority function
     */
    private int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    /**
     * σ0 function
     *
     * Formula: σ0^{256}(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x)
     *
     * @param x Input value
     * @return Result of the σ0 function
     */
    private int sigma0(int x) {
        return rightRotate(x, 7) ^ rightRotate(x, 18) ^ rightShift(x, 3);
    }

    /**
     * σ1 function
     *
     * Formula: σ1^{256}(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x)
     *
     * @param x Input value
     * @return Result of the σ1 function
     */
    private int sigma1(int x) {
        return rightRotate(x, 17) ^ rightRotate(x, 19) ^ rightShift(x, 10);
    }

    /**
     * Σ0 function
     *
     * Formula: Σ0^{256}(x) = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x)
     *
     * @param x Input value
     * @return Result of the Σ0 function
     */
    private int capSigma0(int x) {
        return rightRotate(x, 2) ^ rightRotate(x, 13) ^ rightRotate(x, 22);
    }

    /**
     * Σ1 function
     *
     * Formula: Σ1^{256}(x) = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x)
     *
     * @param x Input value
     * @return Result of the Σ1 function
     */
    private int capSigma1(int x) {
        return rightRotate(x, 6) ^ rightRotate(x, 11) ^ rightRotate(x, 25);
    }

    /**
     * Padding the message (pre-processing)
     *
     * Steps:
     * 1. Append a single '1' bit
     * 2. Append k '0' bits, where k is the smallest non-negative solution to:
     * ℓ + 1 + k ≡ 448 mod 512
     * 3. Append the 64-bit representation of the original message length ℓ
     *
     * @param message The input message to be hashed
     * @return The padded message
     */
    private byte[] padMessage(byte[] message) {
        // Get original message length in bits
        long originalLength = (long) message.length * 8;

        // 1 byte for 0x80 marker + 8 bytes for the length field → total 9 extra bytes
        // Compute number of zero bytes needed so total length is multiple of 64
        int paddingBytes = 64 - ((message.length + 9) % 64);
        if (paddingBytes < 0) {
            paddingBytes += 64;
        }

        // Create padded message array
        byte[] padded = new byte[message.length + 1 + paddingBytes + 8];

        // Copy original message
        System.arraycopy(message, 0, padded, 0, message.length);

        // Append a single '1' bit (0x80 in byte terms)
        padded[message.length] = (byte) 0x80;

        // Append '0' bits (already zeros in the array)

        // Append the original length as a 64-bit big-endian integer
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(originalLength);
        byte[] lengthBytes = buffer.array();

        System.arraycopy(lengthBytes, 0, padded, padded.length - 8, 8);

        return padded;
    }

    /**
     * Process a single 512-bit block
     *
     * @param block The 512-bit block to process (as 16 32-bit words)
     */
    private void processBlock(int[] block) {
        // Prepare message schedule (step 1)
        int[] w = new int[64];

        // First 16 words are the same as the block
        System.arraycopy(block, 0, w, 0, 16);

        // Remaining words are calculated using σ functions
        for (int t = 16; t < 64; t++) {
            // Formula: W_t = σ1^{256}(W_{t-2}) + W_{t-7} + σ0^{256}(W_{t-15}) + W_{t-16}
            w[t] = sigma1(w[t - 2]) + w[t - 7] + sigma0(w[t - 15]) + w[t - 16];
        }

        // Initialize working variables (step 2)
        int a = hash[0];
        int b = hash[1];
        int c = hash[2];
        int d = hash[3];
        int e = hash[4];
        int f = hash[5];
        int g = hash[6];
        int h = hash[7];

        // Main loop (step 3)
        for (int t = 0; t < 64; t++) {
            // Formula: T1 = h + Σ1^{256}(e) + Ch(e, f, g) + K_t + W_t
            int t1 = h + capSigma1(e) + ch(e, f, g) + K[t] + w[t];

            // Formula: T2 = Σ0^{256}(a) + Maj(a, b, c)
            int t2 = capSigma0(a) + maj(a, b, c);

            // Update working variables
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Compute intermediate hash value (step 4)
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    /**
     * Compute the SHA-256 hash of a message
     *
     * @param message The input message
     * @return The SHA-256 hash as a byte array
     */
    public byte[] hash(byte[] message) {
        // Reset hash to initial values
        hash = INITIAL_HASH.clone();

        // Pad the message
        byte[] padded = padMessage(message);

        // Process each 512-bit block
        for (int i = 0; i < padded.length; i += 64) {
            // Extract 512-bit block
            byte[] blockBytes = Arrays.copyOfRange(padded, i, i + 64);

            // Convert to 16 32-bit words (big-endian)
            int[] block = new int[16];
            ByteBuffer buffer = ByteBuffer.wrap(blockBytes);
            buffer.order(ByteOrder.BIG_ENDIAN);

            for (int j = 0; j < 16; j++) {
                block[j] = buffer.getInt();
            }

            // Process the block
            processBlock(block);
        }

        // Convert hash to byte array
        ByteBuffer result = ByteBuffer.allocate(32);
        result.order(ByteOrder.BIG_ENDIAN);

        for (int value : hash) {
            result.putInt(value);
        }

        return result.array();
    }

    /**
     * Convert a byte array to a hexadecimal string
     *
     * @param bytes The byte array to convert
     * @return Hexadecimal string representation
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}