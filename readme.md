# Keepin SDK Verify for java 

## SDK 소개

## 주요 기능
+ SP 로서 Keepin 앱에 요청한 서명 또는 VP 를 검증
+ Keepin 앱에서 VC 를 발급받기 위해 AA 에게 전달한 VP 검증

### SDK 추가



##### Gradle

```gradle
// build.gradle
dependencies {
	implementation 'com.github.METADIUM:keepin-verify-sdk:0.2.3'
}
```

##### Maven

아래설정 pom.xml 에 추가

```xml
<!-- pom.xml -->
<dependency>
	<groupId>com.github.METADIUM</groupId>
	<artifactId>keepin-verify-sdk</artifactId>
	<version>0.2.3</version>
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
String rsaJwk = jwk.toJSONString();                     // SP 서버에서 사용할 Private Key
String rsaPublicJwk = jwk.toPublicJWK().toJSONString(); // 관리자에 등록한 Public Key 

// Load RSA key
RSAKey key = (RSAKey)JWK.parse(rsaJwk);
```

### Auth 서버에서 전달받은 서명검증 및 VC 확인

#### 인증 요청 값 설정
```java
// 미리 설정된 값
String serviceId = "";                  // 발급된 service id
RSAPrivateKey privateKey = getPriKey(); // Keepin 인증 서버에 등록한 RSA 개인키

// Keepin 앱에 인증 요청 시 넘겨준 파라미터
String state = "";    // 인증 요청하기 위해 생성한 UUID 값
int type = "";        // 인증 요청한 타입. 서비스 등록한 인증 타입
String dataHash = ""; // 인증 요청한 data의 hash 값

// 인증 요청 후 응답 받은 파라미터
String code = "";
```

#### Keepin 인증 서버에서 사용자 인증 데이터를 획득

요청 URL
  + BusanKeepin : https://bauth.mykeepin.com/didauth/v1/verify/${serviceId}/${state}/${code}
  + MyKeepin    : https://testauth.metadium.com/didauth/v1/verify/${serviceId}/${state}/${code}

응답 JSON

```json
 {
   "status": 200,
   "data": {
     "did": "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000009b4",
     "vp": "eyJlbmMiOiJBM.....lIV26kw2NCjDV4",
     "signature": "0xdd99b82c3b4d0825f32707e8d86633379edf65571a1c8a3c4334266a928bac85040b2462d8205192895891c6ebb987f2fa5a576f81e3f23fbe21c86f70adf9ae1c"
   }
 }
```


파라미터 설명
  + did : 인증한 사용자의 DID
  + vp : 사용자가 전달한 암호화된 데이터
  + signature : 사용자 서명값   


```java
// 인증서버 API 를 호출 하여 did, vp, signature 값을 설정한다.
String did = "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000009b4";
String vp = "eyJlbmMiOiJBM.....lIV26kw2NCjDV4";
String signature = "0xdd99b82c3b4d0825f32707e8d86633379edf65571a1c8a3c4334266a928bac85040b2462d8205192895891c6ebb987f2fa5a576f81e3f23fbe21c86f70adf9ae1c";

// 사용자 DID 로 검증객체 생성
DidVerifier verifier = new DidVerifier(did);

// 사용자 인증 서명값을 검증한다.
if (!verifier.verifySignaure(serviceId, state, code, type, dataHash, signature)) {
	// 검증 실패
	return;
}

// 전달 받은 데이터를 가지고 있는 RSA private key 로 복호화
if (verifier.extract(vp, privateKey)) {
	// 추출할 정보 설정
	String presentaionInfoJsonString = ".."; // 앱 등록 시 전달 받은 presentation json 정보
	PresentationInfo presentationInfo = new ObjectMapper().readValue(presentaionInfoJsonString,  PresentationInfo.class);
	
	// 요청한 데이터를 얻는다. 순서는 PresentationInfo 에 나열된 순서
	try {
		List<ClaimNameValue> claims = verifier.getClaims(presentationInfo, true);

	
		// 데이터 가져와서 사용
		// claims.get(0).getValue()
		// claims.get(1).getValue()
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
```
