package com.prajaram.jwt.sample;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.IntegrityException;
import org.jose4j.lang.JoseException;

/**
 * This java component is responsible for decrypting the JWT for STS.
 * 
 * This component will first decrypt the token using AES 128 algorithm and
 * verify the signature of the token using SHA 256 algorithm. This also verifies
 * the token expiration.
 * 
 * Signature key, encryption key, ttl are configurable at client application
 * level.
 * 
 */

public class TokenDecryptor {

	
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
	
	public String signatureKey;
	
	public String encryptionKey;
	
	/**
	 * Below method will be called from mule for decrypting and validating JWT
	 * signature.
	 * 
	 * @param signKey
	 * @param encKey
	 * @param jwtToken
	 *
	 * @return Object - Json object containing jwt payload or error payload
	 **/
	public String decrypt( String jwtToken) throws Exception {
		JsonWebEncryption jsonWebEncryption = new JsonWebEncryption();
		jsonWebEncryption.setKey(new AesKey(getEncryptionKey().getBytes()));
		try {
			jsonWebEncryption.setCompactSerialization(jwtToken);
			final String jwt = jsonWebEncryption.getPayload();
			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime()
					.setVerificationKey(new HmacKey(getSignatureKey().getBytes())).build();
			JwtClaims jwtClaims = null;
			jwtClaims = jwtConsumer.processToClaims(jwt);
			return jwtClaims.toJson();

		} catch (InvalidJwtSignatureException e) {
			System.out.println("validation failure:" + e.getMessage());
			return ("{\"status\": \"error\",\"statusCode\": \"10021\",\"statusDescription\": \"Invalid token in the request.\",\"details\": \""
					+ e.getMessage().toString().replaceAll("\"", "'") + "\"}");
		} catch (InvalidJwtException e) {
			String error = e.getMessage().toString().replaceAll("\"", "'");
			System.out.println("validation failure:" + e.getMessage());
			return ("{\"status\": \"error\",\"statusCode\": \"10023\",\"statusDescription\": \"Token is expired.\",\"details\": \""
					+ error.substring(error.indexOf("Additional details: ")) + "\"}");
		} catch (IntegrityException e) {
			System.out.println("validation failure:" + e.getMessage());
			return ("{\"status\": \"error\",\"statusCode\": \"10021\",\"statusDescription\": \"Invalid token in the request.\",\"details\": \""
					+ e.getMessage().toString().replaceAll("\"", "'") + "\"}");
		} catch (JoseException e) {
			System.out.println("validation failure:" + e.getMessage());
			return ("{\"status\": \"error\",\"statusCode\": \"10021\",\"statusDescription\": \"Invalid token in the request.\",\"details\": \""
					+ e.getMessage().toString().replaceAll("\"", "'") + "\"}");
		} catch (Exception e) {
			System.out.println("decryption  failure:" + e.getMessage());
			return ("{\"status\": \"error\",\"statusCode\": \"10020\",\"statusDescription\": \"Internal Server Error.\",\"details\": \""
					+ e.getMessage().toString().replaceAll("\"", "'") + "\"}");
		}
	}

}
