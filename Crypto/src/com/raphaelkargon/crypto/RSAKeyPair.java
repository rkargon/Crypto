package com.raphaelkargon.crypto;

import java.util.Arrays;

public class RSAKeyPair {
	public RSAPublicKey pub_key;
	public RSAPrivateCRTKey priv_key;
	
	public RSAKeyPair(RSAPublicKey pub, RSAPrivateCRTKey priv){
		this.pub_key = pub;
		this.priv_key = priv;
	}
	
	@Override
	public String toString()
	{
		return "Public key: "+Arrays.toString(pub_key.getEncoded())+"\n"+"Private key: "+Arrays.toString(priv_key.getEncoded())+"\n";
	}
}
