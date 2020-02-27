# MyKeepin Server SDK for Java

## SDK 소개

## 주요 기능

## 사용법

### SDK 추가

Gradle

```gradle


```

Maven

```xml

```

### 서명확인 및 VC 얻기

```java
// 미리 설정된 값
String serviceId = "";				// 발급된 service id
RSAPrivateKey privateKey = ...;		// Auth 서버에 등록한 RSA 키의 개인키

// 서버에 생성한 값 설정
String state = "";						// 인증 요청하기 위해 생성한 state
int type = "";							// 인증 요청 타입
String dataHash = "";					// 인증 요청한 data의 hash값

// 앱에서 전달 받은 code 값 설정
String code = "";						// 인증 초기화 후 Auth 서버에서 발급한 code 값

// serviceId, state, code 로 인증 데이터 요청 (/didauth/verify/{service_id}/{state}/{code})

// Auth 서버에서 전달 받은 값 설정
String did = "";
String signature = "";
String vp = "";

// 사용자 DID 로 검증객체 생성
AuthResultVerifier verifier = new AuthResultVerifier(did);

// 검증
if (verifier.verifySignaure(serviceId, state, code, type, dataHash, signature)) {
	// 검증 성공
}
else {
	// 검증 실패
}

// VP 복호화 몇 VP/VC 검증
verifier.extractCredentials(vp, privateKey);

List<VerifiableCredential> vcList = verifier.getVerifiableCredentials();	// 모든 VC 가져오기

VerifiableCredential vc1 = verifier.findVerifiableCredential("${didOfIssuer}", "NameCredential");	// 지정한 issuer 와 credential 이름으로 VC 조회

```
