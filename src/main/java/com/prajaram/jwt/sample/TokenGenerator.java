package com.prajaram.jwt.sample;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

/**
 * This java component is responsible for generating the JWT for STS.
 * 
 * This component will first sign the token using HMAC 256 algorithm and encrypt
 * the token using AES 128 algorithm.
 * 
 * Signature key, encryption key, ttl are confgurable at client application
 * level.
 * 
 */

public class TokenGenerator{

	
	String kid;
	public void setKid(String kid) {
		this.kid= kid;
	}
	
	public void setSignatureKey(String key) {
		this.signatureKey = key;
	}

	public void setEncryptionKey(String key) {
		this.encryptionKey = key;
	}

	public String getSignatureKey() {
		return this.signatureKey;
	}

	public String getEncryptionKey() {
		return this.encryptionKey;
	}
	
	public String getKid() {
		return this.kid;
	}


	/**
	 * Below method will be called from mule for signing and encrypting the JWT
	 * 
	 * signatureKey,encryptionKey,jwtPayload,kid flow variables should be
	 * available before calling this component.
	 */
	
	public String encryptToken(String payload) throws Exception {
		JsonWebSignature jws = new JsonWebSignature();
		jws.setPayload(payload);
		jws.setKey(new HmacKey(getSignatureKey().getBytes()));
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
		String signedToken = jws.getCompactSerialization();
		String kid = getKid();
		String jwt = encrypt(signedToken, getEncryptionKey(), kid);
		return jwt;
	}

	/**
	 * Below method is used to encypt the String using key and kid
	 * 
	 * @param toEncrypt
	 * @param key
	 * @param kid
	 * 
	 * @return String - Encrypted String
	 */
	private String encrypt(String toEncrypt, String key, String kid) {

		JsonWebEncryption jsonWebEncryption = new JsonWebEncryption();
		jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
		jsonWebEncryption
				.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
		jsonWebEncryption.setHeader("typ", "JWT");
		jsonWebEncryption.setHeader("kid", kid);
		jsonWebEncryption.setPayload(toEncrypt);
		jsonWebEncryption.setKey(new AesKey(key.getBytes()));
		try {
			return jsonWebEncryption.getCompactSerialization();
		} catch (JoseException e) {
			System.out.println("Error Occured while encrypting the token:" + e.getMessage());
			throw new RuntimeException(e);
		}
	}

	/**
	 * Key sued to sign the jwt
	 */
	public String signatureKey;
	/**
	 * Key used to encrypt the jwt
	 */
	public String encryptionKey;
}
