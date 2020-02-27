package com.metadium.provider.sdk;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.metadium.provider.sdk.exception.DidNotFoundException;
import com.metadium.provider.sdk.utils.Bytes;
import com.metadium.provider.sdk.utils.Hash;
import com.metadium.vc.VerifiableCredential;
import com.metadium.vc.VerifiablePresentation;
import com.metadium.vc.VerifiableSignedJWT;
import com.metadium.vc.util.Numeric;
import com.metaidum.did.resolver.client.DIDResolverAPI;
import com.metaidum.did.resolver.client.DIDResolverResponse;
import com.metaidum.did.resolver.client.crypto.Signature;
import com.metaidum.did.resolver.client.document.DidDocument;
import com.metaidum.did.resolver.client.document.PublicKey;
import com.metaidum.did.resolver.client.util.Hex;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jwt.SignedJWT;

/**
 * Auth 서버에서 전달된 signature 와 verifiable credential 을 검증.
 * <p>
 * 
 * @author ybjeon
 *
 */
public class AuthResultVerifier {
	private final Logger logger = LoggerFactory.getLogger(AuthResultVerifier.class);
	
	private DidDocument userDidDocument;
	
	private Map<String, DidDocument> didDocCache = new HashMap<>();
	
	private List<VerifiableCredential> vcList = new ArrayList<>();
	
	/**
	 * 사용자의 DID 로 객체를 생성한다.
	 * 
	 * @param userDid 사용자 DID. Auth 서버에서 전달받은 did
	 * @throws IOException resolver 에서 did document 요청 실패 
	 */
	public AuthResultVerifier(String userDid) throws IOException, DidNotFoundException {
		userDidDocument = getDidDocument(userDid);

		if (logger.isDebugEnabled()) {
			logger.debug("init with "+userDid);
		}
	}
	
	private DidDocument getDidDocument(String did) throws IOException, DidNotFoundException {
		try {
			DIDResolverResponse response = DIDResolverAPI.getInstance().requestDocument(did, false);
			DidDocument didDocument = response.getDidDocument();
			
			if (didDocument == null) {
				// 조회 실패. DID 가 존재하지 않거나 다른 에러
				throw new DidNotFoundException(response.getMessage()+" : "+did);
			}
			return didDocument;
		}
		catch (IOException e) {
			throw e;
		}
	}
	
	/**
	 * Auth 서버에서 전달받은 signature 를 검증한다.
	 * 
	 * @param serviceId		발급받은 service id
	 * @param state			인증 요청 시 생성한 state 값
	 * @param code			Auth 서버에서 발급된 code
	 * @param type			인증 요청 시 type
	 * @param dataHash		인증 요청 시 data hash 값
	 * @param signature		Auth 서버에서 전달받은 사용자 서명 값
	 * @return 검증 결과
	 * @throws SignatureException invalid signature
	 */
	public boolean verifySignaure(String serviceId, String state, String code, int type, String dataHash, String signature) throws SignatureException {
		// make nonce
		byte[] packed = Bytes.concat(code.getBytes(),
				serviceId.getBytes(),
				Numeric.toBytesPadded(BigInteger.valueOf(type), 32),
				state.getBytes(),
				dataHash.getBytes(StandardCharset.UTF_8)
				);
		byte[] nonce = Hash.sha3(packed);
		
		// ec-recover 후 address 가 사용자의 did document 에 있는지 확인한다.
		try {
			String address = Signature.addressFromSignature(nonce, signature);
			
			if (logger.isDebugEnabled()) {
				logger.debug("Ec-recover nonce={} signature={} address={}", Hex.toHexString(nonce), signature, address);
			}
			
			return userDidDocument.hasPublicKeyWithAddress(address);
		}
		catch (SignatureException e) {
			throw e;
		}
	}
	
	
	private JWEObject decryptJWE(String jweString, RSAPrivateKey privateKey) {
		try {
			// decrypt jwe
			JWEObject jwe = JWEObject.parse(jweString); 
			jwe.decrypt(new RSADecrypter(privateKey));
			return jwe;
		}
		catch (ParseException | JOSEException e) {
			if (logger.isErrorEnabled()) {
				logger.error("Verifiable presentation JWE parse or decrypt error", e);
			}
		}
		return null;
	}
	
	private SignedJWT verifyJWS(String jwsString, DidDocument signerDidDocument) {
		try {
			// getissuer, kid
			SignedJWT jwt = SignedJWT.parse(jwsString);
			String issuer = jwt.getJWTClaimsSet().getIssuer();
			String keyId = jwt.getHeader().getKeyID();
			
			// get did document with issuer
			if (signerDidDocument == null) {
				signerDidDocument = didDocCache.get(issuer);
				if (signerDidDocument == null) {
					try {
						signerDidDocument = getDidDocument(issuer);
						didDocCache.put(issuer, signerDidDocument);
					}
					catch (IOException | DidNotFoundException e) {
						if (logger.isErrorEnabled()) {
							logger.error("Error getting did document. "+issuer);
						}
						return null;
					}
				}
			}
			
			// get public key with kid
			PublicKey publicKeyOfIssuer = signerDidDocument.getPublicKey(keyId);
			if (publicKeyOfIssuer == null) {
				if (logger.isErrorEnabled()) {
					logger.error("Not found keyID in did document "+issuer);
				}
				return null;
			}

			// verify jws
			ECPublicKey userPublicKey = (ECPublicKey)publicKeyOfIssuer.getPublicKey();
			if (jwt.verify(new ECDSAVerifier(userPublicKey))) {
				return jwt;
			}
		}
		catch (Exception e) {
			if (logger.isErrorEnabled()) {
				logger.error("JWS parse or verify error", e);
			}
		}
		return null;
	}
	
	/**
	 * Auth 서버에서 전달 받은 encrypt 된 presentation 을 decryption 후 presentation, credential 을 검증한다.
	 * <p/>
	 * 
	 * @param jwePresentation	Auth 서버에서 전달 받은 암호화된 VP
	 * @param privateKey		서비스에서 생성한 RSA 개인키. 공개키는 Auth 서버에 등록.
	 * @return 정상적인 복호화와 VP/VC 검증이 성공하면 true 를 반환
	 */
	public boolean extractCredentials(String jwePresentation, RSAPrivateKey privateKey) {
		// Decrypt JWE
		JWEObject jwe = decryptJWE(jwePresentation, privateKey);
		if (jwe == null) {
			return false;
		}
		if (logger.isDebugEnabled()) {
			logger.debug("JWE decrypted alg={}, enc={}", jwe.getHeader().getAlgorithm().toString(), jwe.getHeader().getEncryptionMethod().toString());
		}

		
		// Verify signed verifiable presentation
		SignedJWT jwt = verifyJWS(jwe.getPayload().toString(), userDidDocument);
		if (jwt == null) {
			return false;
		}
		
		// saved vp
		VerifiablePresentation vp;
		try {
			vp = (VerifiablePresentation)VerifiableSignedJWT.toVerifiable(jwt);
		}
		catch (ParseException | JOSEException e) {
			if (logger.isErrorEnabled()) {
				logger.error("JWS to verifiable presentation convert error", e);
			}
			return false;
		}
		if (logger.isDebugEnabled()) {
			logger.debug("Verified VP types={}, holder={}", vp.getTypes(), vp.getHolder().toString());
		}
		
		// extract vc
		for (Object o : vp.getVerifiableCredentials()) {
			if (o instanceof String) {
				SignedJWT vcJwt = verifyJWS((String)o, null);
				if (vcJwt == null) {
					return false;
				}
				
				// Add vc
				try {
					VerifiableCredential vc = (VerifiableCredential)VerifiableSignedJWT.toVerifiable(vcJwt);
					vcList.add(vc);
					if (logger.isDebugEnabled()) {
						logger.debug("Verified VC types={}, issuer={}", vc.getTypes(), vc.getIssuer().toString());
					}
				}
				catch (JOSEException | ParseException e) {
					if (logger.isErrorEnabled()) {
						logger.error("JWS to verifiable credential convert error", e);
					}
					return false;
				}
			}
		}
		
		return true;
	}
	
	/**
	 * 나열된 VC 들 중에 주어진 issuer 의 DID 와 credential 의 이름으로 VC를 조회한다.
	 * @param issuerDid			조회할 issuer 의 did
	 * @param credentialName	조회할 VC 이름
	 * @return 조회된 VC. 조건에 맞는 VC 가 없는 경우 null 반환
	 */
	public VerifiableCredential findVerifiableCredential(String issuerDid, String credentialName) {
		for (VerifiableCredential vc : vcList) {
			if (vc.getIssuer().toString().equals(issuerDid) && vc.getTypes().contains(credentialName)) {
				return vc;
			}
		}
		return null;
	}
	
	/**
	 * 검증된 VC 들을 얻는다.
	 * @return VP 의 모든 VC 반환
	 */
	public List<VerifiableCredential> getVerifiableCredentials() {
		return vcList;
	}
	
}
