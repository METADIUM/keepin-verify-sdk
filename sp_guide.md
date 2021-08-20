# SP 가이드

## Keepin과 연동하여 인증 데이터를 받기 위한 RSA key 준비

#### KEY 생성

생성 후 PublicKey 는 서비 정보와 함께 전달하여 인증 서버에 등록해야 한다.  


##### Web 에서 생성
	
Json Web Key RSA 로 생성. Key Size 2048 Fixed.  
[Generate Site](https://mkjwk.org/)

##### JavaCode 로 생성
```java
RSAKey jwk = new RSAKeyGenerator(2048).generate();
String rsaJwk = jwk.toJSONString();                     // Private Key
String rsaPublicJwk = jwk.toPublicJWK().toJSONString(); // Public Key 
```


#### KEY 로딩

[nimbus-jose-java](https://connect2id.com/products/nimbus-jose-jwt) 라이브러리 필요.  

```java
RSAKey key = RSAKey.parse("${JWK}");
RSAPrivateKey = key.toRSAPrivateKey();

```

## 앱에서 Keepin 으로 인증 요청

앱 설정 및 연동 방법은 Android/iOS SDK 문서 확인  
인증 요청 시 아래의 값들이 필요하며 앱이나 서버에서 생성  

- state : 인증 요청하기 위해 고유한 값. UUID 형식
- type : 서비스 등록 시 할당 받은 인증 타입. 이 값에 따라 요청하는 데이터가 달라짐.
- data : 사용자 서명 시 message 에 같이 포함될 값. null 가능

사용자가 인증이 완료되면 앱에 code 값을 반환하며 위의 값과 code 값을 서버로 보내어 검증하고 데이터를 획득한다. 



## VerifiableCredentail, VerifiablePresentation 검증. (META 만 검증 가능)

```java
// 인증서버 API 를 호출 하여 did, vp, signature 값을 설정한다.
String did = "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000009b4";
String vp = "eyJlbmMiOiJBM.....lIV26kw2NCjDV4";
String signature = "0xdd99b82c3b4d0825f32707e8d86633379edf65571a1c8a3c4334266a928bac85040b2462d8205192895891c6ebb987f2fa5a576f81e3f23fbe21c86f70adf9ae1c";

String serviceId = "..."; // 서비스 등록 시 할당받은 ID
RSAPrivate privateKey = ..; // 로드한 RSA private key

// 사용자 DID 로 검증객체 생성
DidVerifier verifier = new DidVerifier(did);

// 사용자 인증 서명값을 검증한다.
if (!verifier.verifySignaure(serviceId, state, code, type, data, signature)) {
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
		List<ClaimNameValue> claims = verifier.getClaims(presentationInfo, false);

	
		// 데이터 가져와서 사용
		// PresentationInfo 에 나열되어 있는 순서대로 정렬되어 있음
		String email = claims.get(0).getValue();
		String mobileNumber = claims.get(1).getValue();
		
		// claim 에 대한 Credential 확인
		String credentialName = claims.get(0).getCredentialName();
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

## PresentationInfo

서비스 등록 후 각 인증 Type 에 대한 Presentation 정보를 json 으로 받을 수 있다.

예제)

```json
  {
    "vp": "TestAppContractPresentation",
    "vcs": [
      {
        "did": "did:meta:0000000000000000000000000000000000000000000000000000000000004f82",
        "vc": "EmailCredential",
        "name": "email"
      },
      {
        "did": "did:meta:0000000000000000000000000000000000000000000000000000000000004f82",
        "vc": "MobileNumberCredential",
        "name": "mobileNumber"
      }
    ]
  }
```
