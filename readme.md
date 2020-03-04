# MyKeepin SDK Verify for java 

## SDK 소개

## 주요 기능
+ SP 로서 MyKeepin 앱에 요청한 서명 또는 VP 를 검증
+ MyKeepin 앱에서 VC 를 발급받기 위해 AA 에게 전달한 VP 검증

### SDK 추가

Gradle

```gradle


```

Maven

```xml

```

### Auth 서버에서 전달받은 서명검증 및 VC 확인

```java
// 미리 설정된 값
String serviceId = "";                  // 발급된 service id
RSAPrivateKey privateKey = getPriKey(); // Auth 서버에 등록한 RSA 키의 개인키

// 서버에 생성한 값 설정
String state = "";    // 인증 요청하기 위해 생성한 state
int type = "";        // 인증 요청 타입
String dataHash = ""; // 인증 요청한 data의 hash값

// 앱에서 전달 받은 code 값 설정
String code = ""; // 인증 초기화 후 Auth 서버에서 발급한 code 값

// Auth 서버에 serviceId, state, code 로 인증 결과 데이터 요청한다. (/didauth/verify/{service_id}/{state}/{code})

// Auth 서버에서 전달 받은 값 설정
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
if (verifier.extractCredentialsFromEncrytPresentation(vp, privateKey)) {
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

```