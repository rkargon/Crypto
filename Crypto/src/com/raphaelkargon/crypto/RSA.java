package com.raphaelkargon.crypto;
import java.math.BigInteger;
import java.security.*;
import java.util.Random;

/**
 * Implements RSA encryption using BigIntegers. Can be used as an object, which
 * contains the public and private keys as member objects, or statically, passing
 * BigInteger keys to the encrypt and decrypt functions as necessary.
 * <br>
 * NOTE: RSA can only encrypt and decrypt a message that is shorter than the bit-ength of the modulus. 
 * Thus, 1024-bit RSA can only encrypt 1024/8 = 128 ASCII character strings. RSA is not 
 * used to encrypt whole files or long messages. Instead, other algorithms are used to encrypt these
 * messages, and RSA is used to transmit the encryption keys securely between parties.
 *<br><br>
 * TODO: Add padding algorithm to make the encryption more secure. 
 * 
 * @author Raphael Kargon
 * @version 1.0
 */
public class RSA {

	private BigInteger modulus;
	private BigInteger public_exponent;
	private BigInteger private_exponent;
	
	/**
	 * @return the modulus
	 */
	public BigInteger getModulus() {
		return modulus;
	}

	/**
	 * @return the public_exponent
	 */
	public BigInteger getPublic_exponent() {
		return public_exponent;
	}

	/**
	 * @return the private_exponent
	 */
	public BigInteger getPrivate_exponent() {
		return private_exponent;
	}

	/**
	 * Creates a new RSA object with a randomly generated pair of primes, each 1024 bits long.
	 * (This is 2048-bit RSA)
	 * 
	 * @see #RSA(int)
	 */
	public RSA()
	{
		this(2048);
	}
	
	/**
	 * Creates a new RSA object with randomly generated primes, with a specified bit 
	 * length for the modulus (If bit length is odd, will use bits-1)
	 * 
	 * @param bits The number of bits the RSA modulus will have. 
	 */
	
	public RSA(int bits)
	{
		this(BigInteger.probablePrime(bits/2, new SecureRandom()), BigInteger.probablePrime(bits/2, new SecureRandom()));
	}
	
	/**
	 * Creates a new RSA object with the given modulus (n), public exponent (e),
	 * and private exponent (d) as BigInts. 
	 * 
	 * NOTE: This constructor does NOT check if these are valid values.
	 * 
	 * @param n The modulus of the encryption, it should be the product of two prime numbers
	 * @param e The public exponent, used with the modulus to encrypt messages. Should be less than modulus.
	 * @param d The private exponent, used with the modulus to decrypt messages. Should be less than modulus
	 */
	public RSA(BigInteger n, BigInteger e, BigInteger d)
	{
		this.modulus = n;
		this.public_exponent = e;
		this.private_exponent = d;
	}
	
	/**
	 * Creates a new RSA object with the given modulus (n), public exponent (e),
	 * and private exponent (d) as hexadecimal Strings. 
	 * 
	 * @param n Hexadecimal String of modulus.
	 * @param e Hexadecimal String of public exponent.
	 * @param d Hexadecimal String of private exponent.
	 * 
	 * @see #RSA(BigInteger, BigInteger, BigInteger)
	 */
	public RSA(String n, String e, String d)
	{
		this.modulus = new BigInteger(n, 16);
		this.public_exponent = new BigInteger(e, 16);
		this.private_exponent = new BigInteger(d, 16);
	}
	
	/**
	 * Creates a new RSA object with the specified pair of prime numbers.
	 * It will generate a modulus, public key, and private key, which can
	 * later be used to encrypt and decrypt messages.<br><br>
	 * 
	 * <b>Process:</b><br><br>
	 * 
	 * {@code modulus = p*q}<br><br>
	 * 
	 * {@code phi = (p-1)*(q-1)}<br><br>
	 * 
	 * {@code public_exponent} is a number less than {@code phi} that is coprime to {@code phi}. By
	 * default, {@code public_exponent = 2^16+1 = 65537}, since it is prime and allows 
	 * for faster encryption.<br>
	 * If {@code public_exponent} is greater than or not coprime to {@code phi}, it is regenerated
	 * to meet those criteria.<br><br>
	 * 
	 * {@code private_exponent} is the modular inverse of {@code public_exponent}, using {@code phi} as the modulus.
	 * 
	 * @param p A prime number.
	 * @param q Another prime number, not equal to p.
	 */
	public RSA(BigInteger p, BigInteger q)
	{
		modulus = p.multiply(q); //mod = p*q
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); //phi = (p-1)*(q-1)
		public_exponent = BigInteger.valueOf(65537); //by default, e is 2^16 -1 = 65537 (makes for efficient encryption)
		
		//if default exponent is greater than modulus, or is not coprime with (p-1)*(q-1), regenerate public exponent
		while(public_exponent.compareTo(phi)==1 || !phi.gcd(public_exponent).equals(BigInteger.ONE)){
			public_exponent = BigInteger.probablePrime(phi.bitLength()-1, new SecureRandom());
		}
			
		private_exponent = public_exponent.modInverse(phi); 
	}
	
	/**
	 * Encrypts a string and returns it as a BigInteger. This method calls the static {@link #encrypt(BigInteger, BigInteger, String)}
	 * with {@code this} object's member values.
	 * 
	 * @see RSA#encrypt(BigInteger, BigInteger, String)
	 * 
	 * @param msg The message to be encrypted.
	 * @return The encrypted message as a BigInteger.
	 * @throws RSAException 
	 */
	public BigInteger encrypt(String msg) throws RSAException
	{
		return RSA.encrypt(modulus, public_exponent, msg);
	}
	
	/**
	 * Encrypts a string using a given modulus and public key.
	 * The message is converted to a BigInteger byte-by-byte, and then raised 
	 * to the power of the exponent, modulus the modulus. 
	 * 
	 * @param mod The RSA modulus 
	 * @param e The public exponent used to encrypt the message
	 * @param msg The String containing a message to be encrypted
	 * 
	 * @return The encrypted message as a BigInteger
	 * @throws RSAException 
	 */
	public static BigInteger encrypt(BigInteger mod, BigInteger e, String msg) throws RSAException
	{
		/* SOME SORT OF PADDING ALGORITHM GOES HERE */
		if(e.compareTo(mod)==1) throw new RSAException("RSA Error: Cannot encrypt, public exponent is larger than modulus!\n");
		else if ((new BigInteger(msg.getBytes())).compareTo(mod)==1) throw new RSAException("RSA Error: Cannot encrypt, message is larger than modulus!\n");
		return (new BigInteger(msg.getBytes())).modPow(e, mod);
	}
	
	/**
	 * Decrypts a message as a BigInteger, using the static {@link #decrypt(BigInteger, BigInteger, BigInteger)}
	 * with {@code this} object's member values.
	 * 
	 * @see RSA#decrypt(BigInteger, BigInteger, BigInteger)
	 * 
	 * @param cypher An encrypted messages
	 * @return The decrypted message as a String
	 * @throws RSAException 
	 */
	public String decrypt(BigInteger cypher) throws RSAException
	{
		return decrypt(modulus, private_exponent, cypher);
	}
	
	/**
	 * Decrypts a string using a given modulus and private key.
	 * The BigInteger cypher is raised to the power of the private key, modulus
	 * the modulus, and then converted byte by byte to a String.
	 * 
	 * @param mod The RSA modulus
	 * @param d The private exponent used to decrypt the message
	 * @param cypher The encrypted message as a BigInteger
	 * @return The decrypted String message
	 * @throws RSAException 
	 */
	public static String decrypt(BigInteger mod, BigInteger d, BigInteger cypher) throws RSAException
	{
		if(d.compareTo(mod)==1) throw new RSAException("RSA Error: Cannot encrypt, public exponent is larger than modulus!\n");
		else if (cypher.compareTo(mod)==1) throw new RSAException("RSA Error: Cannot encrypt, message is larger than modulus!\n");
		
		BigInteger output = cypher.modPow(d, mod);
		
		/* DE-PADDING SHOULD GO HERE*/
		
		return new String(output.toByteArray());
	}
	
	/** (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "RSA [modulus=" + modulus + ", public_exponent="
				+ public_exponent + ", private_exponent=" + private_exponent
				+ "]";
	}

	/**
	 * Tests the RSA class by sending a "Hello World!" message using 1024 bit RSA
	 */
	public static void main(String[] args) {
		String msg = "Hello World!";
		System.out.println(msg);
		
		RSA keypair = new RSA(1024);
		System.out.println("RSA keys generated: "+keypair.toString());
		
		BigInteger cypher = null;
		String output = null;
		
		try {
			cypher = keypair.encrypt(msg);
		} catch (RSAException e) {
			e.printStackTrace();
			System.exit(0);
		}
		System.out.println(cypher);
		try {
			output = keypair.decrypt(cypher);
		} catch (RSAException e) {
			e.printStackTrace();
			System.exit(0);
		}
		System.out.println(output);
		
	}
	
}
