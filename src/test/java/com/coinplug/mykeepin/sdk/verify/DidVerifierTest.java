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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestTemplate;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;

import com.coinplug.mykeepin.sdk.verify.PresentationInfo.CredentialInfo;
import com.coinplug.mykeepin.sdk.verify.exception.CredentialException;
import com.coinplug.mykeepin.sdk.verify.exception.DidNotFoundException;
import com.coinplug.mykeepin.sdk.verify.exception.PresentationException;
import com.coinplug.mykeepin.utils.Bytes;
import com.coinplug.mykeepin.utils.Hash;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
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
import com.nimbusds.jose.jwk.RSAKey;
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
		if (encryptPublicKey == null) {
			return signedVP.serialize();
		}
		
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512), new Payload(signedVP.serialize()));
		jwe.encrypt(new RSAEncrypter(encryptPublicKey));
		
		return jwe.serialize();
    }
    
    private String generateNonce(String serviceId, String state, String code, int type, String data) {
		// make nonce
		byte[] packed = Bytes.concat(code.getBytes(StandardCharset.UTF_8),
				serviceId.getBytes(StandardCharset.UTF_8),
				Numeric.toBytesPadded(BigInteger.valueOf(type), 32),
				state.getBytes(StandardCharset.UTF_8)
				);
		
		if (data != null) {
			packed = Bytes.concat(packed, data.getBytes(StandardCharset.UTF_8));
		}
		
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
		vcList.add(nameVcInfo);
		CredentialInfo birthVcInfo = new CredentialInfo();
		birthVcInfo.attestatorAgencyDid = ISSUER_DID;
		birthVcInfo.name = "BirthOfDateCredential";
		birthVcInfo.claimName = "birth";
		vcList.add(birthVcInfo);
		
		presentationInfo.credentials = vcList;
		
		try {
			List<ClaimNameValue> claims = verifier.getClaims(presentationInfo, false);
			
			ClaimNameValue nameClaim = claims.get(0);
			ClaimNameValue birthClaim = claims.get(1);
			
			assertEquals(nameClaim.getName(), "name");
			assertEquals(nameClaim.getValue(), "전영배");
			assertEquals(nameClaim.getCredentialName(), "NameCredential");
			assertEquals(birthClaim.getName(), "birth");
			assertEquals(birthClaim.getValue(), "19770206");
			assertEquals(birthClaim.getCredentialName(), "BirthOfDateCredential");

			presentationInfo = new ObjectMapper().readValue("{\"vp\":\"TestPresentation\",\"vcs\":[{\"did\":\"did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382\",\"vc\":\"NameCredential\",\"name\":\"name\",\"type\":\"string\"},{\"did\":\"did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382\",\"vc\":\"BirthOfDateCredential\",\"name\":\"birth\",\"type\":\"string\"}]}",  PresentationInfo.class);
			claims = verifier.getClaims(presentationInfo, false);
			
			nameClaim = claims.get(0);
			birthClaim = claims.get(1);
			
			assertEquals(nameClaim.getName(), "name");
			assertEquals(nameClaim.getCredentialName(), "NameCredential");
			assertEquals(nameClaim.getValue(), "전영배");
			assertEquals(birthClaim.getName(), "birth");
			assertEquals(birthClaim.getValue(), "19770206");
			assertEquals(birthClaim.getCredentialName(), "BirthOfDateCredential");

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
	
	
	@Test
	public void testMd() {
		String serializedVP;
		try {
			serializedVP = issueVP(USER_DID, USER_KID, USER_PRIVATE_KEY, ISSUER_DID, ISSUER_KID, ISSUER_PRIVATE_KEY, null);
		} catch (JOSEException e) {
			return;
		}
		
		try {
			// VP 에서 DID 확인
			SignedJWT signedJWT = SignedJWT.parse(serializedVP);
			String userDid = signedJWT.getJWTClaimsSet().getIssuer();
			
			// DID 가 META 인 경우만 처리
			if (userDid.startsWith("did:meta:")) {
				try {
					DidVerifier verifier = new DidVerifier(userDid);
					
					// VP, VC 검증
					if (!verifier.extract(serializedVP)) {
						// VP 또는 VC 가 올바르지 않거나 검증 실패
						return;
					}
					
					List<VerifiableCredential> vcList = verifier.getCredentials();
					
					for (VerifiableCredential vc : vcList) {
						URI issuer = vc.getIssuer();                                                  // VC 발급자. ex) did:meta:0000000...0003343
						Collection<String> types = vc.getTypes();                                     // verifiable type. ["VerifiableCredentail", "TestCredential"]
						Date issueDate = vc.getIssunaceDate();                                        // VC 발급일자
						Date expireDate = vc.getExpriationDate();                                     // VC 만료일자
						URI id = vc.getId();                                                          // VC 식별자
						Map<String, Object> subject = (Map<String, Object>)vc.getCredentialSubject(); // VC claims
//						vc.getCredentialStatusType()
						
						subject.get("name");
						subject.get("birth");
					}
				} catch (DidNotFoundException e) {
					// 존재하지 않는 DID
					return;
				} catch (IOException e) {
					// resolver 와의 통신 에러
					return;
				}
			}
			
			
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * 인증 서버 응답 객체
	 * @author ybjeon
	 *
	 */
	public class AuthServerResponse {
		private int status;
		private Data data;
		private String code;
		private String message;
		
		public AuthServerResponse(int status, Data data) {
			super();
			this.status = status;
			this.data = data;
		}
		
		public AuthServerResponse() {
		}
		
		public int getStatus() {
			return status;
		}

		public void setStatus(int status) {
			this.status = status;
		}

		public Data getData() {
			return data;
		}

		public void setData(Data data) {
			this.data = data;
		}

		public String getCode() {
			return code;
		}

		public void setCode(String code) {
			this.code = code;
		}

		public String getMessage() {
			return message;
		}

		public void setMessage(String message) {
			this.message = message;
		}

		public class Data {
			private String did;
			private String vp;
			private String signature;
			
			public Data() {
			}
			
			public Data(String did, String vp, String signature) {
				this.did = did;
				this.vp = vp;
				this.signature = signature;
			}

			public String getDid() {
				return did;
			}

			public String getVp() {
				return vp;
			}

			public String getSignature() {
				return signature;
			}
		}
	}
	
	@Test
	public void testSample() throws ParseException, JOSEException, JsonMappingException, JsonProcessingException {
		RSAKey key = RSAKey.parse("\"{\n" + 
				"    \"\"p\"\": \"\"0rXHxJQTAGh2Qxp2SENBGUKMzujIvPe8DjJ3w3HT8859_WpP4UDvc2v4o14HxO9KkmRSgayh5iSBXg1Vd24cKUKWdCL_rZyxIezaEUp_HI5T91m-79CTUAtTNic_sWqUDx0vlgyozvULsvTsALLWRXTE8j4l7-XOt7LpJoiIyys\"\",\n" + 
				"    \"\"kty\"\": \"\"RSA\"\",\n" + 
				"    \"\"q\"\": \"\"xg7fBYnqM7G0HA97Dom1e2wjUe9arHIbtsMktt6blwtDr0t02w93EmHyfU2VUQKbvnN7ViKLf1bAX-41_ax_jr_ab8V9fwxq9hmhdvNnDGdv0DO8kj2fy4NmClpRMrwpbocsiKnXD9dCWOezSAtfd0TpZ9ooA-TG9e8yfwSwiJc\"\",\n" + 
				"    \"\"d\"\": \"\"VB4VtM_XbfkcWbaxkBbUGApfS-J8XUXg2PEuAvA6IP8_k3fWDBmCC7Ci326wNBGyukDJJhMYdl-2OE95t978fM8pwoMyEX3fuYv4kiCyeTYr48vkht1UUxs1q5VZEp212jScyafUPMpWKlY6K0MRQA-1hWSVU7WrXOn881f-IO5qSOBCXAiF3vDyPQL-2jjCsDxAlHM_ze9nDFSuAfW4EsIolHxHo31SrheM9FCCuT9tsHI6dDpTSyYbO98zjTB5Bjb0QG_RB9QqT5Fo95uxr6lEn6RB8oVF4IJzsh1TkZof_BodwWiiQcwScy1t5ig2Gva3A-Xvh23d6dNAUXFJPQ\"\",\n" + 
				"    \"\"e\"\": \"\"AQAB\"\",\n" + 
				"    \"\"qi\"\": \"\"eZxcSAxcbW7NkgIRmVi9ghquY73DjYqx9aId1E_90cW_B4PEhmE-38qUUJ-20eA7E1NYiTs7tE4VpB5ky5P6ddv-clPENrW3hukMAnZXErs9pwzpPTtDb7Z9SarLDw7hH7F7guiPuCiglDM7KvL-70IMqnBmJCMdj5fQFHN84nU\"\",\n" + 
				"    \"\"dp\"\": \"\"tNuKiFSAqsz_FUHVXNk9Oy1AJyjvhCMvqw_udDdzscT_p1BlF_bgkLWQSMkg6gxqeZTarKs8m4mh8NSJE2XTjia1dSHFS4M_FttxoX3L9PrFX34MwVLJ3t6ZodW2edX9F6v5eFWNX3Y9gHFxUHgwKpW7piFp9qvN7ycFsClpINk\"\",\n" + 
				"    \"\"dq\"\": \"\"xdWe8lJjjYVo6kqQWeI2VHWdBj_3K5_DjRh5-Ox9MDABSP0vWY2mG8eYx48SolvfpCqIPW6-NtE50dkJNz3yIG4FTHZRt_F4eiD6Bu50tZAwwSCcsNs7Xbb_20GCMBKBtDTzyAMWnm0fidzPWRx7HJDKMIFaTSFdl9V5dCUEDTs\"\",\n" + 
				"    \"\"n\"\": \"\"owTWA99b-8uKkBVIJFb3pDzzK6fLXtVMMyjJo7yaeIMelM9ISXUaln_4XqtHlOGsIy6yHf6r9az1ujsrJwttE6wU4EP8AhbD3ajSrZ-i7opgK8i9hFz0lHZfc1bL_DSpW-HseJUGeigJySZNHvLW4T_tQ78CEaGAlWJy6PDc_rsipzkN5w0y04y5fZowvVIBQOe27Y-CCmJ-DDijNolAOkUtrCshZ3lZ1wzBLewYgmZlEcp1WQNZH3ygLcDaW5VHOCqNSSr_Egap7jXkC5Ph11E3A9VY-HW2gHi12vwevmneIgpUtvynfHcElMm-6PeM5AzESzLDd1qStC_Qji6uXQ\"\"\n" + 
				"}\"\n" + 
				"");
		RSAPrivateKey privateKey = key.toRSAPrivateKey();
		String serviceId = "ad4d4c20-0df1-11eb-b5c1-fa163e0f872f"; // 서비스 등록 시 할당받은 ID
		
		String state = "...";    // redirect url 로 넘어온 "state" 값
		String code = "...";     // redirect url 로 넘어온 "code" 값
		String dataHash = "..."; // 인증 요청시 입력한 dataHash 값
		
		AuthServerResponse response;
		try {
			String url = "https://auth.blockchainbusan.kr/didauth/v1/verify/"+serviceId+"/"+state+"/"+code;
			HttpHeaders headers = new HttpHeaders();
			headers.add("user-agent", "Application");
			HttpEntity<String> entity = new HttpEntity<>(headers);
			RestTemplate rest = new RestTemplate();
			response = rest.exchange(url, HttpMethod.GET, entity, AuthServerResponse.class).getBody();
			
			if (response.getStatus() != 200) {
				// 인증서버에서 데이터를 못가지고 왔음
				return;
			}
		}
		catch (Exception e) {
			// 네트워크 또는 응답 에러
			return;
		}
		
		String did = response.getData().getDid();
		String signature = response.getData().getSignature();
		String vp = response.getData().getVp();

		// 검증 객체 생성
		DidVerifier verifier;
		try {
			verifier = new DidVerifier(did);
		}
		catch (IOException e) {
			// DID document 를 가져오지 못했음
			return;
		}
		catch (DidNotFoundException e) {
			// 존재하지 않는 사용자 DID
			return;
		}
		
		// 서명 검증
		if (!verifier.verifySignaureForAuth(serviceId, state, code, 1, dataHash, signature)) {
			// 서명 검증 실패. 실제 사용자가 보낸 데이터가 아님
			return;
		}
		
		// VP 복호화, VP/VC 검증
		if (!verifier.extract(vp, privateKey)) {
			// VP 복호화 또는 검증 실패
			return;
		}

		// 앱 등록 시 전달 받은 presentation json 정보
		String presentaionInfoJsonString = "[{\"vp\":\"BMEventPresentation\",\"vcs\":[{\"did\":\"did:meta:000000000000000000000000000000000000000000000000000000000000755c\",\"vc\":\"NameCredential\",\"name\":\"name\"},{\"did\":\"did:meta:000000000000000000000000000000000000000000000000000000000000755c\",\"vc\":\"MobileNumberCredential\",\"name\":\"mobileNumber\"}]}]";
		PresentationInfo presentationInfo = new ObjectMapper().readValue(presentaionInfoJsonString,  PresentationInfo.class);

		// 요청한 데이터를 얻는다. 순서는 PresentationInfo 에 나열된 순서
		try {
			List<ClaimNameValue> claims = verifier.getClaims(presentationInfo, true);
		
			// 데이터 가져와서 사용
			String name = (String)claims.get(0).getValue();
			String mobileNumber = (String)claims.get(1).getValue();
			
			save(did, name, mobileNumber);
		}
		catch (IllegalStateException e) {
			// extract 함수를 호출 하지 않았을 때 발생
		}
		catch (PresentationException e) {
			// 요청한 VP 가 아닌 경우 발생
		}
		catch (CredentialException ce) {
			// 받은 데이터의 오류 처리
			switch (ce.getErrorCode()) {
			case NotFoundCredential:
				// 필요한 인증정보를 포함하고 있지 않음
				break;
			case ExpiredCredential:
				// 전달받은 인증정보가 만료되었음
				break;
			case NotFoundClaim:
				// 요청한 정보의 값이 없음
				break;
			case RevokedCredential:
				// 인증정보가 인증자에 의해 폐기 되었음
				break;
			case IssuerServerError:
				// 인증자 서버에러
				break;
			}
		}
	}
	
	private void save(String a, String b, String c) {
	}
	
	
	@Test
	public void test365() throws Exception {
		String presentaionInfoJsonString ="{\"vp\":\"BMEventPresentation\",\"vcs\":[{\"did\":\"did:meta:000000000000000000000000000000000000000000000000000000000000755c\",\"vc\":\"NameCredential\",\"name\":\"name\"},{\"did\":\"did:meta:000000000000000000000000000000000000000000000000000000000000755c\",\"vc\":\"MobileNumberCredential\",\"name\":\"mobileNumber\"}]}";
		PresentationInfo presentationInfo = new ObjectMapper().readValue(presentaionInfoJsonString, PresentationInfo.class);
		
				
//		String pInfo = "{\"vp\":\"BwaUserPresentation\",\"vcs\":[{\"did\":\"did:meta:000000000000000000000000000000000000000000000000000000000000755c\",\"vc\":\"NameCredential\",\"name\":\"name\"},{\"did\":\"did:meta:000000000000000000000000000000000000000000000000000000000000755c\",\"vc\":\"MobileNumberCredential\",\"name\":\"mobileNumber\"}]}";
//		PresentationInfo presentationInfo = new ObjectMapper().readValue(pInfo,  PresentationInfo.class);
		
		String vp = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bWV0YTowMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA4MzAyI01ldGFNYW5hZ2VtZW50S2V5I2RmZTgyMjM1NTg3ZDk2MDMyNWI2M2U2MzAyNDRjOWRiNDA1NjE2ZjAiLCJ0eXAiOiJKV1QifQ.eyJub25jZSI6IjkzRDI5MEY1LTY2QjktNDhBOC1BMTQ5LTcyNEFGOEEzMkRCRiIsImlzcyI6ImRpZDptZXRhOjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDgzMDIiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczpcL1wvdzNpZC5vcmdcL2NyZWRlbnRpYWxzXC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJCd2FVc2VyUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SnJhV1FpT2lKa2FXUTZiV1YwWVRvd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREEzTlRWakkwMWxkR0ZOWVc1aFoyVnRaVzUwUzJWNUl6bGxORGs1Tm1Rd1lURXlZakJpTmpGaE9EUmpNekEwWkRCbFpEY3pObVkwWldJeU5qa3hNemtpTENKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKRlV6STFOa3NpZlEuZXlKemRXSWlPaUprYVdRNmJXVjBZVG93TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQTRNekF5SWl3aWFYTnpJam9pWkdsa09tMWxkR0U2TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdOelUxWXlJc0ltVjRjQ0k2TVRZMk5qSTNOems1T1N3aWFXRjBJam94TmpBek1qWTBNalU1TENKdWIyNWpaU0k2SWpjNU56YzNZelUxTFdabFpqQXRORE0yWXkwNE9Ea3hMV0V6TW1FeU1qa3lNR1EyWmlJc0luWmpJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2x3dlhDOTNNMmxrTG05eVoxd3ZZM0psWkdWdWRHbGhiSE5jTDNZeElsMHNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKT1lXMWxRM0psWkdWdWRHbGhiQ0pkTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SnVZVzFsSWpvaTdaV2M3S2VFN0l1ZEluMTlMQ0pxZEdraU9pSm9kSFJ3Y3pwY0wxd3ZZWFIwWlhOMFlYUnZjaTVpYkc5amEyTm9ZV2x1WW5WellXNHVhM0k2TVRnNE9EbGNMMjF2WW1sc1pWd3ZZM0psWkdWdWRHbGhiSE5jTDBReWJsQlBNRkZDVVhKTE9HTm5WRjlPV0VST1EzY2lmUS5uaVB0LVE3MFdYbl94TkNxRjAwZ0MyN1phbEtldHItZ2x1Y3dfanZONV9pM2xPM1IwTUJxeGFfektuY2JpcGswWXFZVms3TDlvQTNIVk1yX090alZlUSIsImV5SnJhV1FpT2lKa2FXUTZiV1YwWVRvd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREEzTlRWakkwMWxkR0ZOWVc1aFoyVnRaVzUwUzJWNUl6bGxORGs1Tm1Rd1lURXlZakJpTmpGaE9EUmpNekEwWkRCbFpEY3pObVkwWldJeU5qa3hNemtpTENKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKRlV6STFOa3NpZlEuZXlKemRXSWlPaUprYVdRNmJXVjBZVG93TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQTRNekF5SWl3aWFYTnpJam9pWkdsa09tMWxkR0U2TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdOelUxWXlJc0ltVjRjQ0k2TVRZMk5qSTNOems1T1N3aWFXRjBJam94TmpBek1qWTBNalU1TENKdWIyNWpaU0k2SWpjek1HRXhZV1U1TFRRek1EY3RORGc1WXkwNE9UWmlMVEZrTVRJNVpUWmpZV00yTkNJc0luWmpJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2x3dlhDOTNNMmxrTG05eVoxd3ZZM0psWkdWdWRHbGhiSE5jTDNZeElsMHNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKTmIySnBiR1ZPZFcxaVpYSkRjbVZrWlc1MGFXRnNJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltMXZZbWxzWlU1MWJXSmxjaUk2SWpBeE1EVTJNVEV5TnpRM0luMTlMQ0pxZEdraU9pSm9kSFJ3Y3pwY0wxd3ZZWFIwWlhOMFlYUnZjaTVpYkc5amEyTm9ZV2x1WW5WellXNHVhM0k2TVRnNE9EbGNMMjF2WW1sc1pWd3ZZM0psWkdWdWRHbGhiSE5jTDBReWJsQlBNRkZDVVhKTE9HTm5WRjlPV0VST1EzY2lmUS4yZjRwRTJMN2wzMGxoZjhCRXhUdWtVYkh3d3h5aldlQlliUFc2ZmtsampfOXlZWHdUVm1STDREOFM3a3p6cWh5UGZnTUdkb1RqTnUwcmY4R2RJYmxrdyJdfX0.OkUiyguk5p5bDNLLspzjJGdJzhzVXCwhIgmzIInTBJZWy-1eOErDRMfXHO3VgfX26megU8ZUbH-A6LASJgJM3A";
		
		DidVerifier verifier = new DidVerifier("did:meta:0000000000000000000000000000000000000000000000000000000000008302");
		if (verifier.extract(vp)) {
		
			List<ClaimNameValue> claims = verifier.getClaims(presentationInfo, true);
			
			// 데이터 가져와서 사용
			String name = (String)claims.get(0).getValue();
			String mobileNumber = (String)claims.get(1).getValue();
			
			System.out.println("name = "+name);
			System.out.println("mobileNumber = "+mobileNumber);
		}
	}
}


