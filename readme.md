# MyKeepin SDK Verify for java 

## SDK 소개

## 주요 기능
+ SP 로서 MyKeepin 앱에 요청한 서명 또는 VP 를 검증
+ MyKeepin 앱에서 VC 를 발급받기 위해 AA 에게 전달한 VP 검증

### SDK 추가

##### Maven repository 설정 <= maven central 에 deploy 전 까지 임시로 사용

[라이브러리](https://bitbucket.org/coinplugin/mykeepin-verify-sdk/downloads/mykeepin-verify-sdk-0.2.0.zip) 다운로드 후 ~/.m2/com/coinplug/mykeepin-verify-sdk/0.2.0 디렉토리에 압축 해제


##### Gradle

```gradle
// build.gradle
dependencies {
	implementation 'com.coinplug:mykeepin-verify-sdk:0.2.0'
}
```

#####Maven

아래설정 pom.xml 에 추가

```xml
<!-- pom.xml -->
<dependency>
	<groupId>com.coinplug</groupId>
	<artifactId>mykeepin-verify-sdk</artifactId>
	<version>0.2.0</version>
</dependency>
```

### Logging

Logging use slf4j.

```xml
<!-- logback.xml -->
<logger name="com.coinplug.mykeepin.sdk.verify" level="DEBUG" additivity ="false">
	<appender-ref ref="console" />
</logger>
```

### Rsa key 준비

[nimbus-jose-java](https://connect2id.com/products/nimbus-jose-jwt) 라이브러리 필요.  

```java
// Generate RSA Key. 2048 bit 이상만 지원
RSAKey jwk = new RSAKeyGenerator(2048).generate();
String rsaJwk = jwk.toJSONString();							// SP 서버에서 사용할 Private Key
String rsaPublicJwk = jwk.toPublicJWK().toJSONString();	// 관리자에 등록한 Public Key 

// Load RSA key
RSAKey key = (RSAKey)JWK.parse(rsaJwk);
```

### Auth 서버에서 전달받은 서명검증 및 VC 확인

```java
// 미리 설정된 값
String serviceId = "";                  // 발급된 service id
RSAPrivateKey privateKey = getPriKey(); // Auth 서버에 등록한 RSA 개인키

// 서버에 생성한 값 설정
String state = "";    // 인증 요청하기 위해 생성한 state
int type = "";        // 인증 요청한 타입
String dataHash = ""; // 인증 요청한 data의 hash값

// 앱에서 전달 받은 code 값 설정
String code = ""; // 인증 초기화 후 Auth 서버에서 발급한 code 값

// Auth 서버에 serviceId, state, code 로 인증 결과 데이터 요청하여 did, signature, vp 를 얻는다.
// 요청 URL : https://testauth.metadium.com/didauth/v1/verify/${serviceId}/${state+}/${code}
String did = "";
String signature = "";
String vp = "";

// 사용자 DID 로 검증객체 생성
DidVerifier verifier = new DidVerifier(did);

// 검증만 필요한 경우 signature 를 검증한다.
if (!verifier.verifySignaure(serviceId, state, code, type, dataHash, signature)) {
	// 검증 실패
	return;
}

// 전달 받은 VP 를 확인이 필요한 경우 VP 복호화 몇 VP/VC 검증 
if (verifier.extractCredentialsFromEncryptPresentation(vp, privateKey)) {
	// 지정한 issuer 와 credential 이름으로 VC 조회. 전체 credential 은 getVerifiableCredentials() 사용.
	String didOfRequiredAA = "did:meta:0x.....";
	VerifiableCredential vc1 = verifier.findVerifiableCredential(didOfRequiredAA, "NameCredential");
	
	// 해당 Credential 의 subject(claim) 은 가져온다.
	Map<String, String> subject = (Map<String, String>)nameVC.getCredentialSubject();
	
	String name = subject.get("name");
}

```

### MyKeepin 에서 전달된 VP/VC 검증 및 확인. AA 로 VP 를 전달한 경우

```java
// MyKeepin 에서 전달 받은 VP
String receiveVP = "...";

// VP 에서 user DID 확인
String userDid;
try {
	SignedJWT signedVp = SignedJWT.parse(receiveVP);
	userDid = signedVp.getJWTClaimsSet().getIssuer();
}
catch (ParseException e) {
	// VP 파싱 실패
	return;
}

// 사용자 DID 로 검증객체 생성
DidVerifier verifier = new DidVerifier(userDid);

// VP/VC 검증 
if (verifier.extractCredentialsFromPresentation(receiveVP)) {
	// 지정한 issuer 와 credential 이름으로 VC 조회. 전체 credential 은 getVerifiableCredentials() 사용.
	String didOfRequiredAA = "did:meta:0x.....";
	VerifiableCredential vc1 = verifier.findVerifiableCredential(didOfRequiredAA, "NameCredential");
	
	// 해당 Credential 의 subject(claim) 은 가져온다.
	Map<String, String> subject = (Map<String, String>)nameVC.getCredentialSubject();
	
	String name = subject.get("name");
}

// 새로운 VC 생성
VerifiableCredential newVC = new VerifiableCredential();
newVC.setId(URI.create("http://aa.metadium.com/credential/343"));  	// VC 의 ID. URL 로 VC의 유효성을 해당 URL 로 확인할 수 있어야 함.
newVC.addTypes(Collections.singletonList("NameCredential"));       	// AA 에서 정의한 VC 이름. 관리자에도 등록 되어 있어야 함
newVC.setIssuer(URI.create("did:meta:0x3489384932859420"));        	// AA 의 DID
newVC.setIssuanceDate(issuedDate);                                 	// VC 발급일
newVC.setExpirationDate(expireDate);                             		// VC 만료일
LinkedHashMap<String, String> subject = new LinkedHashMap<>();
subject.put("id", "did:meta:0x11111111120");                        // VC 소유자의 DID 
subject.put("name", "mansud");                                      // VC subject 
newVC.setCredentialSubject(subject);

```