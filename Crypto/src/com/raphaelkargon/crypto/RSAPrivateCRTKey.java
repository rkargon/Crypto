package com.raphaelkargon.crypto;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;

public class RSAPrivateCRTKey implements RSAPrivateCrtKey {

	BigInteger modulus, public_exponent, private_exponent, p, q, exp_p, exp_q, coefficient;
	
	/**
	 * Initializes an RSA key according to the PKCS#1 specification
	 * 
	 * @param modulus
	 * @param public_exponent
	 * @param private_exponent
	 * @param p
	 * @param q
	 * @param exp_p
	 * @param exp_q
	 * @param coefficient
	 */
	public RSAPrivateCRTKey(BigInteger modulus, BigInteger public_exponent,
			BigInteger private_exponent, BigInteger p, BigInteger q,
			BigInteger exp_p, BigInteger exp_q, BigInteger coefficient) {
		super();
		this.modulus = modulus;
		this.public_exponent = public_exponent;
		this.private_exponent = private_exponent;
		this.p = p;
		this.q = q;
		this.exp_p = exp_p;
		this.exp_q = exp_q;
		this.coefficient = coefficient;
	}

	@Override
	public BigInteger getPrivateExponent() {
		return this.private_exponent;
	}

	@Override
	public String getAlgorithm() {
		return "RSA";
	}

	@Override
	public String getFormat() {
		return "PKCS#1";
	}

	@Override
	public byte[] getEncoded() {
		return this.private_exponent.toByteArray();
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	@Override
	public BigInteger getPublicExponent() {
		return this.public_exponent;
	}

	@Override
	public BigInteger getPrimeP() { 
		return this.p;
	}

	@Override
	public BigInteger getPrimeQ() {
		return this.q;
	}

	@Override
	public BigInteger getPrimeExponentP() {
		return this.exp_p;
	}

	@Override
	public BigInteger getPrimeExponentQ() {
		return this.exp_q;
	}

	@Override
	public BigInteger getCrtCoefficient() {
		return this.coefficient;
	}

}
