package com.prajaram.jwt.sample;

/**
 * Hello world!
 *
 */
public class App {
	public static void main(String[] args) throws Exception {

		TokenGenerator generator=new TokenGenerator();
		generator.setEncryptionKey("ABCDEFGHABCDEFGH");
		generator.setSignatureKey("ABCDEFGHABCDEFGHABCDEFGHABCDEFGH");
		generator.setKid("XX-XX-XXXX");
		String payload="{\"name\":\"Rajaram\",\"Age\":26,\"exp\":"+System.currentTimeMillis()+60000+"}";
		String token=generator.encryptToken(payload);
		System.out.println(token);
		TokenDecryptor decryptor=new TokenDecryptor();
		decryptor.setEncryptionKey("ABCDEFGHABCDEFGH");
		decryptor.setSignatureKey("ABCDEFGHABCDEFGHABCDEFGHABCDEFGH");
		String jwtpayload=decryptor.decrypt(token);
		System.out.println(jwtpayload);
	}
}
