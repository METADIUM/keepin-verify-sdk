package com.coinplug.mykeepin.sdk.verify;

import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.coinplug.mykeepin.sdk.verify.PresentationInfo.CredentialInfo;
import com.coinplug.mykeepin.sdk.verify.exception.CredentialException;
import com.coinplug.mykeepin.sdk.verify.exception.DidNotFoundException;
import com.coinplug.mykeepin.sdk.verify.exception.PresentationException;
import com.coinplug.mykeepin.sdk.verify.exception.CredentialException.ErrorCode;
import com.coinplug.mykeepin.utils.Bytes;
import com.coinplug.mykeepin.utils.Hash;
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
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jwt.SignedJWT;

/**
 * Auth 서버에서 전달된 signature 와 verifiable credential 을 검증.
 * <p>
 * 
 * @author ybjeon
 *
 */
public class DidVerifier {
	private final Logger logger = LoggerFactory.getLogger(DidVerifier.class);
	
	private DidDocument userDidDocument;
	
	private Map<String, DidDocument> didDocCache = new HashMap<>();
	
	private VerifiablePresentation vp;
	private List<VerifiableCredential> vcList = new ArrayList<>();
	
	/**
	 * 사용자의 DID 로 객체를 생성한다.
	 * 
	 * @param userDid 사용자 DID. Auth 서버에서 전달받은 did
	 * @throws IOException resolver 에서 did document 요청 실패 
	 */
	public DidVerifier(String userDid) throws IOException, DidNotFoundException {
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
	 * Auth 서버에서 전달받은 DID 의 signature 를 검증한다.
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
	public boolean verifySignaureForAuth(String serviceId, String state, String code, int type, String dataHash, String signature) {
		// make nonce
		byte[] packed = Bytes.concat(code.getBytes(StandardCharset.UTF_8),
				serviceId.getBytes(StandardCharset.UTF_8),
				Numeric.toBytesPadded(BigInteger.valueOf(type), 32),
				state.getBytes(StandardCharset.UTF_8)
				);
		
		if (dataHash != null) {
			packed = Bytes.concat(packed, dataHash.getBytes(StandardCharset.UTF_8));
		}
		
		byte[] nonce = Hash.sha3(packed);
		
		
		return verifySignature(Hex.toHexString(nonce).getBytes(StandardCharset.UTF_8), signature);
	}
	
	/**
	 * DID 로 서명한 signature 를 검증한다.
	 * 
	 * @param nonce			서명한 데이터
	 * @param signature		서명 값. hexstring of R+S+V
	 * @return
	 */
	public boolean verifySignature(byte[] nonce, String signature) {
		// ec-recover 후 address 가 사용자의 did document 에 있는지 확인한다.
		try {
			String address = Signature.addressFromSignature(nonce, signature);
			
			if (logger.isDebugEnabled()) {
				logger.debug("Ec-recover nonce={} signature={} address={}", Hex.toHexString(nonce), signature, address);
			}
			
			return userDidDocument.hasPublicKeyWithAddress(address);
		}
		catch (SignatureException e) {
			if (logger.isDebugEnabled()) {
				logger.warn("Ec-recover failed", e);
			}
			return false;
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
			ECDSAVerifier verifier = new ECDSAVerifier(userPublicKey);
			verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
			if (jwt.verify(verifier)) {
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
	 * presentation, credential 을 검증하고 credential을 객체에 저장한다.
	 * <p/>
	 * 저장된 credential 은 {@link #findVerifiableCredential(String, String)}, {@link #getVerifiableCredentials()} 를 사용하여 가져올 수 있다.
	 * 
	 * @param signedPresentation 서명된 VP.(JWS)
	 * @return 정상적인 복호화와 VP/VC 검증이 성공하면 true 를 반환
	 * @deprecated Use {@link #extract(String)}
	 */
	public boolean extractCredentialsFromPresentation(String signedPresentation) {
		return extract(signedPresentation);
	}
	
	/**
	 * presentation, credential 을 검증하고 credential을 객체에 저장한다.
	 * <p/>
	 * 저장된 credential 은 {@link #findCredential(String, String)}, {@link #getCredentials()} 를 사용하여 가져올 수 있다.
	 * 
	 * @param signedPresentation 서명된 VP.(JWS)
	 * @return 정상적인 복호화와 VP/VC 검증이 성공하면 true 를 반환
	 */
	public boolean extract(String signedPresentation) {
		// Verify signed verifiable presentation
		SignedJWT jwt = verifyJWS(signedPresentation, userDidDocument);
		if (jwt == null) {
			return false;
		}
		
		// saved vp
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
					if (logger.isDebugEnabled()) {
						logger.debug("Verified raw VC={}", vcJwt.serialize());
					}
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
	 * Auth 서버에서 전달 받은 encrypt 된 presentation 을 decryption 후 presentation, credential 을 검증하고 객체에 저장한다.
	 * <p/>
	 * 저장된 credential 은 {@link #findVerifiableCredential(String, String)}, {@link #getVerifiableCredentials()} 를 사용하여 가져올 수 있다.
	 * 
	 * @param encryptPresentation	Auth 서버에서 전달 받은 암호화된 VP
	 * @param privateKey		서비스에서 생성한 RSA 개인키. 공개키는 Auth 서버에 등록.
	 * @return 정상적인 복호화와 VP/VC 검증이 성공하면 true 를 반환
	 * @deprecated Use {@link #extract(String, RSAPrivateKey)}
	 */
	public boolean extractCredentialsFromEncryptPresentation(String encryptPresentation, RSAPrivateKey privateKey) {
		return extract(encryptPresentation, privateKey);
	}
	
	/**
	 * Auth 서버에서 전달 받은 encrypt 된 presentation 을 decryption 후 presentation, credential 을 검증하고 객체에 저장한다.
	 * <p/>
	 * 저장된 credential 은 {@link #findCredential(String, String)}, {@link #getCredentials()} 를 사용하여 가져올 수 있다.
	 * 
	 * @param encryptPresentation Auth 서버에서 전달 받은 암호화된 VP
	 * @param privateKey          서비스에서 생성한 RSA 개인키. 공개키는 Auth 서버에 등록.
	 * @return 정상적인 복호화와 VP/VC 검증이 성공하면 true 를 반환
	 */
	public boolean extract(String encryptPresentation, RSAPrivateKey privateKey) {
		// Decrypt JWE
		JWEObject jwe = decryptJWE(encryptPresentation, privateKey);
		if (jwe == null) {
			return false;
		}
		if (logger.isDebugEnabled()) {
			logger.debug("JWE decrypted alg={}, enc={}", jwe.getHeader().getAlgorithm().toString(), jwe.getHeader().getEncryptionMethod().toString());
		}

		return extract(jwe.getPayload().toString());
	}
	
	/**
	 * 나열된 VC 들 중에 주어진 issuer 의 DID 와 credential 의 이름으로 VC를 조회한다.
	 * @param issuerDid			조회할 issuer 의 did
	 * @param credentialName	조회할 VC 이름
	 * @return 조회된 VC. 조건에 맞는 VC 가 없는 경우 null 반환
	 * @deprecated Use {@link #findCredential(String, String)}
	 */
	public VerifiableCredential findVerifiableCredential(String issuerDid, String credentialName) {
		return findCredential(issuerDid, credentialName);
	}
	
	/**
	 * 나열된 VC 들 중에 주어진 issuer 의 DID 와 credential 의 이름으로 VC를 조회한다.
	 * @param issuerDid			조회할 issuer 의 did
	 * @param credentialName	조회할 VC 이름
	 * @return 조회된 VC. 조건에 맞는 VC 가 없는 경우 null 반환
	 */
	public VerifiableCredential findCredential(String issuerDid, String credentialName) {
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
	 * @deprecated Use {@link #getCredentials()}
	 */
	public List<VerifiableCredential> getVerifiableCredentials() {
		return vcList;
	}

	/**
	 * 검증된 VC 들을 얻는다.
	 * @return VP 의 모든 VC 반환
	 */
	public List<VerifiableCredential> getCredentials() {
		return vcList;
	}

	/**
	 * 검증된 VP 들을 얻는다.
	 * @return VP
	 */
	public VerifiablePresentation getPresentation() {
		return vp;
	}
	
	/**
	 * presentation 정보로 claim 정보를 얻는다.<p/>
	 * 필요하다면 credential 의 id 로 발행자에게 확인할 수 있다.
	 * 
	 * @param presentationInfo  claim 정보를 얻기 위한 presentation 정보
	 * @param useVerifyByIssuer 발행자에게 검증을 받을지 여부. 검증받기 위해 http 통신이 필요
	 * @return claim 정보
	 * @throws IllegalStateException {@link #extract(String)} or {@link #extract(String, RSAPrivateKey)} 을 하지 않은 경우
	 * @throws PresentationException 원하는 Presentation Type 이 아닌 경우 발생
	 * @throws CredentialException   원하는 Credential 이 아니거나 유효하지 않은 경우 발생
	 * 
	 */
	public List<ClaimNameValue> getClaims(PresentationInfo presentationInfo, boolean useVerifyByIssuer) throws PresentationException, CredentialException, IllegalStateException {
		if (presentationInfo == null) {
			return Collections.emptyList();
		}
		if (vp == null || vcList.size() == 0) {
			throw new IllegalStateException("Must call extract");
		}
		
		// Check vp type name
		if (!vp.getTypes().contains(presentationInfo.name)) {
			throw new PresentationException("Presentation types not contains "+presentationInfo.name+". "+vp.getType());
		}
		
		List<ClaimNameValue> retValues = new ArrayList<>();
		Date curDate = new Date();
		
		for (CredentialInfo c : presentationInfo.credentials) {
			// check issuer did, vc type name
			VerifiableCredential findVc = findCredential(c.attestatorAgencyDid, c.name);
			if (findVc == null) {
				throw new CredentialException(ErrorCode.NotFoundCredential, "issuerDid="+c.attestatorAgencyDid+" credentialType="+c.name);
			}
			
			// check expire date
			if (findVc.getExpriationDate() != null) {
				if (curDate.after(findVc.getExpriationDate())) {
					throw new CredentialException(ErrorCode.ExpiredCredential, findVc);
				}
			}
			
			@SuppressWarnings("unchecked")
			Map<String, Object> claims = (Map<String, Object>)findVc.getCredentialSubject();
			
			// check claim
			Object value = claims.get(c.claimName);
			if (value == null) {
				throw new CredentialException(ErrorCode.NotFoundClaim, findVc);
			}
			
			// check id
			if (useVerifyByIssuer && findVc.getId() != null && findVc.getId().getScheme().startsWith("http")) {
				HttpURLConnection conn = null;
				try {
					if (logger.isDebugEnabled()) {
						logger.debug("Search credentail to AA. url="+findVc.getId().toURL().toString());
					}
					
					conn = (HttpURLConnection) findVc.getId().toURL().openConnection();
					conn.setRequestProperty("User-Agent", "Java/DidVerifier");
					conn.connect();
					int statusCode = conn.getResponseCode();
					
					if (logger.isDebugEnabled()) {
						logger.debug("url="+findVc.getId().toURL().toString()+" status="+statusCode);
					}
					
					
					if (statusCode == HttpURLConnection.HTTP_NOT_FOUND) {
						throw new CredentialException(ErrorCode.NotFoundCredential, findVc);
					}
					else if (statusCode == HttpURLConnection.HTTP_GONE) {
						throw new CredentialException(ErrorCode.RevokedCredential, findVc);
					}
					else if (statusCode != HttpURLConnection.HTTP_OK) {
						logger.error("AA server error. status_code="+statusCode);
						throw new CredentialException(ErrorCode.IssuerServerError, findVc);
					}
				}
				catch (IOException e) {
					logger.error("AA server error", e);
					throw new CredentialException(ErrorCode.IssuerServerError, findVc);
				}
				finally {
					if (conn != null) {
						conn.disconnect();
					}
				}
			}
			
			retValues.add(ClaimNameValue.create(c.claimName, value));
		}
		
		return retValues;
	}
	
}
