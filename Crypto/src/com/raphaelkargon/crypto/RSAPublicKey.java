package com.raphaelkargon.crypto;

import java.math.BigInteger;

public class RSAPublicKey implements java.security.interfaces.RSAPublicKey {

	BigInteger modulus, public_exponent;
	
	public RSAPublicKey(BigInteger modulus, BigInteger public_exponent){
		this.modulus = modulus;
		this.public_exponent = public_exponent;
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
		return public_exponent.toByteArray();
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	@Override
	public BigInteger getPublicExponent() {
		return this.public_exponent;
	}

}
