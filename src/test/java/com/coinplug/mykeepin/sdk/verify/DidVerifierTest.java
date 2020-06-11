package com.coinplug.mykeepin.sdk.verify;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;

import com.coinplug.mykeepin.sdk.verify.PresentationInfo.CredentialInfo;
import com.coinplug.mykeepin.sdk.verify.exception.DidNotFoundException;
import com.coinplug.mykeepin.utils.Bytes;
import com.coinplug.mykeepin.utils.Hash;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.metadium.vc.VerifiableCredential;
import com.metadium.vc.VerifiablePresentation;
import com.metadium.vc.VerifiableSignedJWT;
import com.metadium.vc.util.ECKeyUtils;
import com.metadium.vc.util.Numeric;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jwt.SignedJWT;

public class DidVerifierTest {
	
    private static final String ISSUER_DID = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382";
    private static final String ISSUER_KID = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382#MetaManagementKey#59ddc27f5bc6983458eac013b1e771d11c908683";
    private static final BigInteger ISSUER_PRIVATE_KEY_BIG_INT = new BigInteger("fdcdca38d0c62f3564f90afdc4c04c1f936b9edf95b5d8841a70b40cc84cfd90", 16);
    private static final ECPrivateKey ISSUER_PRIVATE_KEY = ECKeyUtils.toECPrivateKey(ISSUER_PRIVATE_KEY_BIG_INT, "secp256k1");

    private static final String ISSUER2_DID = "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000009b5";
    private static final String ISSUER2_KID = "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000009b5#MetaManagementKey#79d8090bf6c5af769307b0d6b39014daa5e295a4";
    private static final BigInteger ISSUER2_PRIVATE_KEY_BIG_INT = new BigInteger("daf1acfb6f0a049bf4e1166140a86d8254b53ebca0f22cc25d9ca452d8162249", 16);
    private static final ECPrivateKey ISSUER2_PRIVATE_KEY = ECKeyUtils.toECPrivateKey(ISSUER2_PRIVATE_KEY_BIG_INT, "secp256k1");

    private static final String USER_DID = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b";
    private static final String USER_KID = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b#MetaManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511";
    private static final BigInteger USER_PRIVATE_KEY_BIG_INT = new BigInteger("86975dca6a36062768cf4b648b5b3f712caa2d1d61fa42520624a8e574788822", 16);
    private static final ECPrivateKey USER_PRIVATE_KEY = ECKeyUtils.toECPrivateKey(USER_PRIVATE_KEY_BIG_INT, "secp256k1");
    

    private static final String USER2_DID = "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000009b4";
    private static final String USER2_KID = "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000009b4#MetaManagementKey#91c511c721c29f8ea9e9e1f3a2602885425662ba";
    private static final BigInteger USER2_PRIVATE_KEY_BIG_INT = new BigInteger("477cdbbe5a3774758e832ed99a3d91a5790090942d73a619aa6b223c4be014f5", 16);
    private static final ECPrivateKey USER2_PRIVATE_KEY = ECKeyUtils.toECPrivateKey(USER2_PRIVATE_KEY_BIG_INT, "secp256k1");

    static {
    	Security.addProvider(new BouncyCastleProvider());
    	System.setProperty(org.slf4j.impl.SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "DEBUG");
    }
    
    private String issueVP(String ownerDid, String ownerKid, ECPrivateKey ownerPrivateKey, String issuerDid, String issuerKid, ECPrivateKey issuerPrivateKey, RSAPublicKey encryptPublicKey) throws JOSEException {
		// make vc by issuer
		VerifiableCredential vc1 = new VerifiableCredential();
		vc1.addTypes(Collections.singletonList("NameCredential"));
		vc1.setIssuer(URI.create(issuerDid));
		vc1.setIssuanceDate(new Date());
		LinkedHashMap<String, String> subject = new LinkedHashMap<>();
		subject.put("id", ownerDid);
		subject.put("name", "전영배");
		vc1.setCredentialSubject(subject);
		
		VerifiableCredential vc2 = new VerifiableCredential();
		vc2.addTypes(Collections.singletonList("BirthOfDateCredential"));
		vc2.setIssuer(URI.create(issuerDid));
		vc2.setIssuanceDate(new Date());
		LinkedHashMap<String, String> subject2 = new LinkedHashMap<>();
		subject2.put("id", ownerDid);
		subject2.put("birth", "19770206");
		vc2.setCredentialSubject(subject2);

		ECDSASigner issuerSigner = new ECDSASigner(issuerPrivateKey);

		SignedJWT signedVC1 = VerifiableSignedJWT.sign(vc1, issuerKid, UUID.randomUUID().toString(), issuerSigner);
		SignedJWT signedVC2 = VerifiableSignedJWT.sign(vc2, issuerKid, UUID.randomUUID().toString(), issuerSigner);
		
		// make vp by user
		VerifiablePresentation vp = new VerifiablePresentation();
		vp.setHolder(URI.create(ownerDid));
		vp.addTypes(Collections.singletonList("TestPresentation"));
		vp.addVerifiableCredential(signedVC1.serialize());
		vp.addVerifiableCredential(signedVC2.serialize());
		SignedJWT signedVP = VerifiableSignedJWT.sign(vp, ownerKid, UUID.randomUUID().toString(), new ECDSASigner(ownerPrivateKey));
		
		// encrypt jwe
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512), new Payload(signedVP.serialize()));
		jwe.encrypt(new RSAEncrypter(encryptPublicKey));
		
		return jwe.serialize();
    }
    
    private String generateNonce(String serviceId, String state, String code, int type, String data) {
		byte[] packed = Bytes.concat(code.getBytes(StandardCharset.UTF_8),
				serviceId.getBytes(StandardCharset.UTF_8),
				Numeric.toBytesPadded(BigInteger.valueOf(type), 32),
				state.getBytes(StandardCharset.UTF_8),
				data.getBytes(StandardCharset.UTF_8)
				);
		byte[] nonce = Hash.sha3(packed);

		return Hex.toHexString(nonce);
    }
    
    
    
	@Test
	public void testVerify() throws DidNotFoundException, IOException, SignatureException {
		String serviceId = "f7c5b186-41b9-11ea-ab1a-0a0f3ad235f2";
		String state = "9017935a-1127-465c-afcf-9b2a3ba22157";
		String code = "8deaef00-3bc2-4420-b1c2-07b01f00142d";
		int type = 0;
		String data = "6B88E30E8540E421FC613B2F0BD0B070F6B3D018DDB79E011135049FBEE881F1";
		
		String orgNonce = "240a4df912798871f5d70a17ef7a654ca91ce232633d66bd1a26de961d9f12f4";

		String nonce = generateNonce(serviceId, state, code, type, data);
		
		assertEquals(orgNonce, nonce);
		
		// make signature
		Sign.SignatureData signData = Sign.signMessage(nonce.getBytes(StandardCharset.UTF_8), ECKeyPair.create(USER_PRIVATE_KEY_BIG_INT));
        ByteBuffer buffer = ByteBuffer.allocate(65);
        buffer.put(signData.getR());
        buffer.put(signData.getS());
        buffer.put(signData.getV());
        
        String signature = org.web3j.utils.Numeric.toHexString(buffer.array());

		// Verify test
		DidVerifier verifier = new DidVerifier(USER_DID);
		assertTrue(verifier.verifySignaureForAuth(serviceId, state, code, type, data, signature));
	}
	
	@SuppressWarnings("unchecked")
	@Test
	public void testVpVerify() throws NoSuchAlgorithmException, JOSEException, DidNotFoundException, IOException {
		//issuer1 rsakey
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		KeyPair keyPair2 = keyPairGenerator.generateKeyPair();
		
		String encryptedVP = issueVP(USER_DID, USER_KID, USER_PRIVATE_KEY, ISSUER_DID, ISSUER_KID, ISSUER_PRIVATE_KEY, (RSAPublicKey)keyPair.getPublic());
		
		com.nimbusds.jose.jwk.RSAKey jwk = new com.nimbusds.jose.jwk.RSAKey.Builder((RSAPublicKey)keyPair.getPublic()).privateKey(keyPair.getPrivate()).build();
		com.nimbusds.jose.jwk.RSAKey jwk2 = new com.nimbusds.jose.jwk.RSAKey.Builder((RSAPublicKey)keyPair.getPublic()).build();
		
		System.out.println("jwk="+jwk.toJSONString());
		System.out.println("jwk2="+jwk2.toJSONString());
		System.out.println("user="+USER_DID);
		System.out.println("issuer="+ISSUER_DID);
		System.out.println("evp="+encryptedVP);
		
		
		
		DidVerifier verifier = new DidVerifier(USER_DID);
		assertTrue(verifier.extract(encryptedVP, (RSAPrivateKey)keyPair.getPrivate()));
		
		PresentationInfo presentationInfo = new PresentationInfo();
		presentationInfo.name = "TestPresentation";
		List<CredentialInfo> vcList = new ArrayList<PresentationInfo.CredentialInfo>();
		CredentialInfo nameVcInfo = new CredentialInfo();
		nameVcInfo.attestatorAgencyDid = ISSUER_DID;
		nameVcInfo.name = "NameCredential";
		nameVcInfo.claimName = "name";
		nameVcInfo.claimValueClass = String.class;
		vcList.add(nameVcInfo);
		CredentialInfo birthVcInfo = new CredentialInfo();
		birthVcInfo.attestatorAgencyDid = ISSUER_DID;
		birthVcInfo.name = "BirthOfDateCredential";
		birthVcInfo.claimName = "birth";
		birthVcInfo.claimValueClass = String.class;
		vcList.add(birthVcInfo);
		
		presentationInfo.credentials = vcList;
		
		try {
			List<ClaimNameValue<?>> claims = verifier.getClaims(presentationInfo, true);
			
			ClaimNameValue<String> nameClaim = (ClaimNameValue<String>) claims.get(0);
			ClaimNameValue<String> birthClaim = (ClaimNameValue<String>) claims.get(1);
			
			assertEquals(nameClaim.getName(), "name");
			assertEquals(nameClaim.getValue(), "전영배");
			assertEquals(birthClaim.getName(), "birth");
			assertEquals(birthClaim.getValue(), "19770206");

			presentationInfo = new ObjectMapper().readValue("{\"vp\":\"TestPresentation\",\"vcs\":[{\"did\":\"did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382\",\"vc\":\"NameCredential\",\"name\":\"name\",\"type\":\"string\"},{\"did\":\"did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382\",\"vc\":\"BirthOfDateCredential\",\"name\":\"birth\",\"type\":\"string\"}]}",  PresentationInfo.class);
			claims = verifier.getClaims(presentationInfo, true);
			
			nameClaim = (ClaimNameValue<String>) claims.get(0);
			birthClaim = (ClaimNameValue<String>) claims.get(1);
			
			assertEquals(nameClaim.getName(), "name");
			assertEquals(nameClaim.getValue(), "전영배");
			assertEquals(birthClaim.getName(), "birth");
			assertEquals(birthClaim.getValue(), "19770206");

		}
		catch (Exception e) {
			e.printStackTrace();
			assertTrue(false);
		}
		
		VerifiableCredential resVc1 = verifier.findCredential(ISSUER_DID, "NameCredential");
		VerifiableCredential resVc2 = verifier.findCredential(ISSUER_DID, "BirthOfDateCredential");
		
		assertNotNull(resVc1);
		assertNotNull(resVc2);
		assertEquals("전영배", ((Map<String, String>)resVc1.getCredentialSubject()).get("name"));
		assertEquals("19770206", ((Map<String, String>)resVc2.getCredentialSubject()).get("birth"));
		
		// not same issuer
		assertNull(verifier.findCredential(ISSUER2_DID, "NameCredential"));
		assertNull(verifier.findCredential(ISSUER2_DID, "BirthOfDateCredential"));

		// other did
		DidVerifier verifier2 = new DidVerifier(USER2_DID);
		assertFalse(verifier2.extract(encryptedVP, (RSAPrivateKey)keyPair.getPrivate()));
		
		// other public key
		assertFalse(verifier.extract(encryptedVP, (RSAPrivateKey)keyPair2.getPrivate()));

		// invalid did
		try {
			new DidVerifier("did:meta:testnet:0000000000000000000000000000000000000000000000000000000000007382");
			assertTrue(false);
		}
		catch (DidNotFoundException e) {
			assertTrue(true);
		}
	}
}
