package com.raphaelkargon.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
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
 * TODO: Comply to PKCS
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
	 * Creates a new RSA object with the specified modulus size. It
	 * will generate a modulus, public key, and private key, which can later be
	 * used to encrypt and decrypt messages.<br>
	 * <br>
	 * 
	 * <b>Process:</b><br>
	 * <br>
	 * Choose two prime numbers <code>p</code>, <code>q</code> with bit length = bits/2<br>
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
	 * @param bits the size in bits of the RSA modulus
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
		
		return new RSAKeyPair(
				new RSAPublicKey(modulus, public_exponent), 
				new RSAPrivateCRTKey(modulus, public_exponent, private_exponent, p, q, exp_p, exp_q, coefficient));
	}
	
	/**
	 * Encrypts a byte array using a given public key. The message is
	 * converted to a BigInteger byte-by-byte, and then raised to the power of
	 * the exponent, modulus the modulus.
	 * 
	 * @param pub the RSA public key 
	 * 
	 * @param msg
	 *            The byte array containing a message to be encrypted
	 * 
	 * @return The encrypted message as a BigInteger
	 * @throws RSAException
	 */
	public static BigInteger encrypt(RSAPublicKey pub, byte[] msg)
			throws RSAException {
		/* SOME SORT OF PADDING ALGORITHM GOES HERE */
		if (pub.public_exponent.compareTo(pub.modulus) == 1)
			throw new RSAException(
					"RSA Error: Cannot encrypt, public exponent is larger than modulus!\n");
		else if ((new BigInteger(msg)).compareTo(pub.modulus) == 1)
			throw new RSAException(
					"RSA Error: Cannot encrypt, message is larger than modulus!\n");
		return (new BigInteger(msg)).modPow(pub.public_exponent, pub.modulus);
	}

	public static BigInteger encryptPKCS(RSAPublicKey pub, byte[] msg, String label) throws RSAException
	{
		
		int k = pub.modulus.bitCount();
		int mLen = msg.length;
		int hLen = MD5.outputLength();
		
		//length checking for label unnecessary: Java's max str length is Integer.MAX_VALUE, should not be a problem for hash functions.
		
		//length checking for message:
		if(mLen > k - 2*hLen - 2) throw new RSAException("Message too long!");
		
		byte[] lHash = MD5.hash(label);
		byte[] PS = new byte[k - mLen - 2*hLen - 2];
		
		//dataBlock = concatenation of lHash || PS || 0x01 || msg
		byte[] dataBlock = new byte[k - hLen - 1];
		for(int i=0; i<mLen; i++) dataBlock[i] = msg[i];
		dataBlock[mLen] = 0x01;
		for(int i=0; i<k-mLen-2*hLen-2; i++) dataBlock[i+mLen+1] = PS[i];
		for(int i=0; i<hLen; i++) dataBlock[i+k-2*hLen-1] = lHash[i];
		
		byte[] seed = new byte[hLen];
		new Random().nextBytes(seed);
		
		return null;
	}
	
	public static BigInteger encryptPKCS(RSAPublicKey pub, byte[] msg) throws RSAException 
	{
		return encryptPKCS(pub, msg, "");
	}

	/**
	 * Decrypts a string using a given modulus and private key. The BigInteger
	 * cypher is raised to the power of the private key, modulus the modulus,
	 * and then converted byte by byte to a String.
	 * 
	 * @param priv the RSA private key
	 * 
	 * @param cypher
	 *            The encrypted message as a BigInteger
	 * @return The decrypted message as a byte array
	 * @throws RSAException
	 */
	
	public static byte[] decrypt(RSAPrivateCRTKey priv, BigInteger cypher)
			throws RSAException {
		if (cypher.compareTo(priv.modulus) == 1)
			throw new RSAException(
					"RSA Error: Cannot encrypt, message is larger than modulus!\n");

		BigInteger m1 = cypher.modPow(priv.exp_p, priv.p);
		BigInteger m2 = cypher.modPow(priv.exp_q, priv.q);
		BigInteger h = m1.subtract(m2).multiply(priv.coefficient).mod(priv.p);
		BigInteger output = m2.add(priv.q.multiply(h));
		
		//BigInteger output = cyphertext.modPow(priv.private_exponent, priv.modulus);

		/* DE-PADDING SHOULD GO HERE */
		return output.toByteArray();
	}

	/**
	 * Tests the RSA class by sending a "Hello World!" message using 1024 bit
	 * RSA
	 */
	public static void main(String[] args) {
		String msg = "Hello World!";
		//System.out.println(msg);

		RSAKeyPair keypair = GetRSAKeyPair();
		//System.out.println("RSA keys generated: \n" + keypair.toString());

		BigInteger cypher = null;
		String output = null;

		try {
			cypher = RSA.encrypt(keypair.pub_key, msg.getBytes());
		} catch (RSAException e) {
			e.printStackTrace();
			System.exit(0);
		}
		//System.out.println(cypher);
		try {
			output = new String(RSA.decrypt(keypair.priv_key, cypher));
		} catch (RSAException e) {
			e.printStackTrace();
			System.exit(0);
		}
		//System.out.println(output);
		
		System.out.println("Message is \""+msg+"\"\nOutput is \""+output+"\"\n"+"Outputs "+(msg.equals(output) ? "" : "DO NOT ") + "match!");

	}

}
