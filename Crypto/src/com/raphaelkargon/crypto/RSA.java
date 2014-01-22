package com.raphaelkargon.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 * Implements RSA encryption using BigIntegers. Can be used as an object, which
 * contains the public and private keys as member objects, or statically,
 * passing BigInteger keys to the encrypt and decrypt functions as necessary. <br>
 * NOTE: RSA can only encrypt and decrypt a message that is shorter than the
 * bit-ength of the modulus. Thus, 1024-bit RSA can only encrypt 1024/8 = 128
 * ASCII character strings. RSA is not used to encrypt whole files or long
 * messages. Instead, other algorithms are used to encrypt these messages, and
 * RSA is used to transmit the encryption keys securely between parties. <br>
 * <br>
 * 
 * @author Raphael Kargon
 * @version 1.0
 */
public class RSA {

	/**
	 * Creates a new RSA object with a randomly generated pair of primes, each
	 * 1024 bits long. (This is 2048-bit RSA)
	 * 
	 * @see GetRSAKeyPair(int)
	 */
	public static RSAKeyPair GetRSAKeyPair() {
		return GetRSAKeyPair(2048);
	}

	/**
	 * Creates a new RSA object with the specified modulus size. It will
	 * generate a modulus, public key, and private key, which can later be used
	 * to encrypt and decrypt messages.<br>
	 * <br>
	 * 
	 * <b>Process:</b><br>
	 * <br>
	 * Choose two prime numbers <code>p</code>, <code>q</code> with bit length =
	 * bits/2<br>
	 * 
	 * {@code modulus = p*q}<br>
	 * <br>
	 * 
	 * {@code phi = (p-1)*(q-1)}<br>
	 * <br>
	 * 
	 * {@code public_exponent} is a number less than {@code phi} that is coprime
	 * to {@code phi}. By default, {@code public_exponent = 2^16+1 = 65537},
	 * since it is prime and allows for faster encryption.<br>
	 * If {@code public_exponent} is greater than or not coprime to {@code phi},
	 * it is regenerated to meet those criteria.<br>
	 * <br>
	 * 
	 * {@code private_exponent} is the modular inverse of
	 * {@code public_exponent}, using {@code phi} as the modulus.
	 * 
	 * @param bits
	 *            the size in bits of the RSA modulus
	 */
	public static RSAKeyPair GetRSAKeyPair(int bits) {
		BigInteger p = BigInteger.probablePrime(bits / 2, new SecureRandom());
		BigInteger q = BigInteger.probablePrime(bits / 2, new SecureRandom());

		BigInteger modulus, public_exponent, private_exponent, exp_p, exp_q, coefficient;

		modulus = p.multiply(q); // mod = p*q
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(
				q.subtract(BigInteger.ONE)); // phi = (p-1)*(q-1)
		public_exponent = BigInteger.valueOf(65537); // by default, e is 2^16 -1
														// = 65537 (makes for
														// efficient encryption)

		// if default exponent is greater than modulus, or is not coprime with
		// (p-1)*(q-1), regenerate public exponent
		while (public_exponent.compareTo(phi) == 1
				|| !phi.gcd(public_exponent).equals(BigInteger.ONE)) {
			public_exponent = BigInteger.probablePrime(phi.bitLength() - 1,
					new SecureRandom());
		}

		private_exponent = public_exponent.modInverse(phi);
		exp_p = public_exponent.modInverse(p.subtract(BigInteger.ONE));
		exp_q = public_exponent.modInverse(q.subtract(BigInteger.ONE));
		coefficient = q.modInverse(p);

		return new RSAKeyPair(new RSAPublicKey(modulus, public_exponent),
				new RSAPrivateCRTKey(modulus, public_exponent,
						private_exponent, p, q, exp_p, exp_q, coefficient));
	}

	/**
	 * Encrypts a byte array using a given public key. The message is converted
	 * to a BigInteger byte-by-byte, and then raised to the power of the
	 * exponent, modulus the modulus.
	 * 
	 * NOTE: This encryption does not use a padding scheme. Use
	 * {@link #encryptPKCS(RSAPublicKey, byte[], String)} for more secure
	 * encryption that conforms to RSAES-OAEP standard.
	 * 
	 * NOTE: Assumes valid RSA public key
	 * 
	 * @param pub
	 *            the RSA public key
	 * 
	 * @param msg
	 *            The byte array containing a message to be encrypted
	 * 
	 * @return The encrypted message as a BigInteger
	 * @throws RSAException
	 */
	public static BigInteger encrypt(RSAPublicKey pub, byte[] msg)
			throws RSAException {
		BigInteger msgInt = new BigInteger(msg);
		// msg >= 0 and msg< modulus
		if (msgInt.signum() == -1 || msgInt.compareTo(pub.modulus) > -1)
			throw new RSAException("Message representative out of range.");
		return msgInt.modPow(pub.public_exponent, pub.modulus);
	}

	/**
	 * Pads a message using RSAES-OAEP standard, and encrypts it using the given
	 * public key.
	 * 
	 * @param pub the RSA public key
	 * @param msg The message to be ecnrypted, as a byte array
	 * @param label An optional label to be used during padding
	 * @return The encrypted message
	 * @throws RSAException
	 */
	public static byte[] encryptPKCS(RSAPublicKey pub, byte[] msg, String label)
			throws RSAException {

		int k = (int) Math.ceil(pub.modulus.bitLength() / 8.0);
		int mLen = msg.length;
		int hLen = MD5.outputLength();

		// length checking for label unnecessary: Java's max str length is
		// Integer.MAX_VALUE, should not be a problem for hash functions.

		// length checking for message:
		if (mLen > k - 2 * hLen - 2)
			throw new RSAException("Message too long.");

		byte[] lHash = MD5.hash(label);
		byte[] PS = new byte[k - mLen - 2 * hLen - 2];

		// dataBlock = concatenation of lHash || PS || 0x01 || msg
		byte[] dataBlock = new byte[k - hLen - 1];
		System.arraycopy(lHash, 0, dataBlock, 0, hLen);
		System.arraycopy(PS, 0, dataBlock, hLen, PS.length);
		dataBlock[hLen + PS.length] = 1;
		System.arraycopy(msg, 0, dataBlock, hLen + PS.length + 1, mLen);

		// fill seed with random bytes
		byte[] seed = new byte[hLen];
		new SecureRandom().nextBytes(seed);

		// generate mask using seed, use this mask on dataBlock and store result
		// in maskedDB
		byte[] dbMask = MGF1(seed, k - hLen - 1);
		byte[] maskedDB = new byte[k - hLen - 1];
		for (int i = 0; i < k - hLen - 1; i++)
			maskedDB[i] = (byte) (dataBlock[i] ^ dbMask[i]);

		// generate mask based on maskedDB
		byte[] seedMask = MGF1(maskedDB, hLen);
		byte[] maskedSeed = new byte[hLen];
		for (int i = 0; i < hLen; i++)
			maskedSeed[i] = (byte) (seed[i] ^ seedMask[i]);

		// encoded message = 0x00 || maskedSeed || maskedDB
		byte[] encodedMessage = new byte[k];
		encodedMessage[0] = 0;
		System.arraycopy(maskedSeed, 0, encodedMessage, 1, hLen);
		System.arraycopy(maskedDB, 0, encodedMessage, 1 + hLen, k - hLen - 1);

		BigInteger cypherInt = encrypt(pub, encodedMessage);
		byte[] cypher = new byte[k], cypherIntArr = cypherInt.toByteArray();

		if (cypherIntArr.length > k && cypherIntArr[0] == 0)
			cypher = Arrays.copyOfRange(cypherInt.toByteArray(), 1, k + 1);
		else
			cypher = Arrays.copyOfRange(cypherInt.toByteArray(), 0, k);

		return cypher;

	}

	public static byte[] encryptPKCS(RSAPublicKey pub, byte[] msg)
			throws RSAException {
		return encryptPKCS(pub, msg, "");
	}

	public static byte[] decryptPKCS(RSAPrivateCRTKey priv, byte[] cypher,
			String label) throws RSAException {
		int k = (int) Math.ceil(priv.modulus.bitLength() / 8.0);
		int hLen = MD5.outputLength();
		byte[] lHash = MD5.hash(label);

		if (cypher.length != k) {
			throw new RSAException("Decryption error.");
		}
		if (k < 2 * hLen + 2)
			throw new RSAException("Decryption error.");

		byte[] encodedMessage = new byte[k], decryptedArr;
		try {
			// takes into account how signage bit may overflow into next byte,
			// be omitted
			decryptedArr = decrypt(priv, new BigInteger(1, cypher));
			if (decryptedArr.length < k && decryptedArr[0] != 0)
				System.arraycopy(decryptedArr, 0, encodedMessage, 1,
						decryptedArr.length);
			else
				encodedMessage = Arrays.copyOfRange(decryptedArr, 0, k);
		} catch (RSAException e) {
			throw new RSAException("Decryption error.");
		}

		// encoded message = 0x00 || maskedSeed || maskedDB
		int Y = encodedMessage[0]; // Y should equal 0
		byte[] maskedSeed = Arrays.copyOfRange(encodedMessage, 1, hLen + 1);
		byte[] maskedDB = Arrays.copyOfRange(encodedMessage, hLen + 1, k);

		// undo masking
		byte[] seedMask = MGF1(maskedDB, hLen);
		byte[] seed = new byte[hLen];
		for (int i = 0; i < hLen; i++)
			seed[i] = (byte) (maskedSeed[i] ^ seedMask[i]);

		byte[] dbMask = MGF1(seed, k - hLen - 1);
		byte[] dataBlock = new byte[k - hLen - 1];
		for (int i = 0; i < k - hLen - 1; i++)
			dataBlock[i] = (byte) (maskedDB[i] ^ dbMask[i]);

		// dataBlock = lHash1 || PS || 0x01 || msg
		byte[] lHash1 = Arrays.copyOfRange(dataBlock, 0, hLen);

		// check if 0x01 byte exists
		int p = hLen;
		try {
			for (p = hLen; dataBlock[p] == 0; p++)
				;
		} catch (ArrayIndexOutOfBoundsException e) {
			throw new RSAException("Decryption error.");
		}

		if (Y != 0 || dataBlock[p] != 1 || !Arrays.equals(lHash, lHash1)) {
			throw new RSAException("Decryption error.");
		}
		byte[] msg = Arrays.copyOfRange(dataBlock, p + 1, k - hLen);

		return msg;
	}

	public static byte[] decryptPKCS(RSAPrivateCRTKey priv, byte[] cypher)
			throws RSAException {
		return decryptPKCS(priv, cypher, "");
	}

	/**
	 * Decrypts a string using a given modulus and private key. The BigInteger
	 * cypher is raised to the power of the private key, modulus the modulus,
	 * and then converted byte by byte to a String.
	 * 
	 * NOTE: Assumes valid RSA private key
	 * 
	 * @param priv
	 *            the RSA private key
	 * 
	 * @param cypher
	 *            The encrypted message as a BigInteger
	 * @return The decrypted message as a byte array
	 * @throws RSAException
	 */

	public static byte[] decrypt(RSAPrivateCRTKey priv, BigInteger cypher)
			throws RSAException {
		if (cypher.signum() == -1 || cypher.compareTo(priv.modulus) > -1)
			throw new RSAException("Cyphertext representative out of range.");

		BigInteger m1 = cypher.modPow(priv.exp_p, priv.p);
		BigInteger m2 = cypher.modPow(priv.exp_q, priv.q);
		BigInteger h = m1.subtract(m2).multiply(priv.coefficient).mod(priv.p);
		BigInteger output = m2.add(priv.q.multiply(h));
		return output.toByteArray();
	}

	/**
	 * A Mask Generation Function based on a hash function. Takes a byte array
	 * of variable length, and outputs a byte array of fixed length.
	 * 
	 * @param mgfSeed
	 *            The seed for the mask generation function
	 * @param maskLen
	 *            The desired output length of the mask
	 * @return A byte array of length <code>maskLen</code>, based on the input
	 *         seed.
	 */
	public static byte[] MGF1(byte[] mgfSeed, int maskLen) {
		int hLen = MD5.outputLength();
		// seed_or_C = mgfSeed || i
		byte[] T = new byte[(int) (hLen * Math.ceil((double) maskLen / hLen))], seed_or_C = new byte[mgfSeed.length + 4];

		System.arraycopy(mgfSeed, 0, seed_or_C, 0, mgfSeed.length);

		// length checking unnecessary, Java's max byte array length is
		// Integer.MAX_VALUE, so maskLen can't be greater than 2^32 * hLen;

		for (int i = 0; i < Math.ceil((double) maskLen / hLen); i++) {

			// update counter by converting i to 4 bytes
			seed_or_C[mgfSeed.length + 0] = (byte) ((i >> 24) & 255);
			seed_or_C[mgfSeed.length + 1] = (byte) ((i >> 16) & 255);
			seed_or_C[mgfSeed.length + 2] = (byte) ((i >> 8) & 255);
			seed_or_C[mgfSeed.length + 3] = (byte) (i & 255);

			// take hash of seed and counter, append to T
			System.arraycopy(MD5.hash(seed_or_C), 0, T, i * hLen, hLen);

		}
		return Arrays.copyOfRange(T, 0, maskLen);
	}

	/**
	 * Tests the RSA class by sending a "Hello World!" message using 1024 bit
	 * RSA
	 */
	public static void main(String[] args) {
		String msg = "Hello yes this is test";

		RSAKeyPair keypair = GetRSAKeyPair();

		byte[] cypher = null;
		String output = null;

		try {
			cypher = RSA.encryptPKCS(keypair.pub_key, msg.getBytes());
		} catch (RSAException e) {
			e.printStackTrace();
			System.exit(0);
		}
		try {
			output = (new String(RSA.decryptPKCS(keypair.priv_key, cypher)));
		} catch (RSAException e) {
			e.printStackTrace();
			System.exit(0);
		}

		output = output.substring(0, output.length() - 1); // trim trailing 0
		System.out.println("Message is \"" + msg + "\"\nOutput is \"" + output
				+ "\"\n" + "Outputs " + (msg.equals(output) ? "" : "DO NOT ")
				+ "match!");
	}

}
