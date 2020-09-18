# AA(AttestationAgency) 가이드 

AA는 앱에 인증서(VerifiableCredentail)를 발급하기 위해서는 모바일 웹으로 제공해야 하며  
앱은 제공되는 모바일 웹을 앱내에 WebView 로 노출하여 발급을 진행한다.

## DID 생성

AA 역할을 하기 위해서는 반드시 DID 를 생성해야 합니다.


[DID CLI Tool](https://drive.google.com/file/d/1lbH4uMg6kyb8eBFJwSDwFGZXfu8-MHdX/view?usp=sharing)을 다운로드 합니다.

#### CLI 사용법
```sh
> java -jar metadium-cli-keygen-0.1.4.jar --help
usage: --help
 -h,--help                                show command list
 -n,--network <mainnet or testnet>            default: testnet
 -o,--output <inputYourOutputDirectory>   report output absolute directory path.
                                          ex) "/var/log". default: your current directory
 -p,--password <inputYourPassword>        password to encrypt for zip. default: 1234
```

#### DID 생성

```sh
>  java -jar metadium-cli-keygen-0.1.4.jar --password 1234567890
```

#### DID 정보 확인

DID 생성 시 생성된 ZIP 파일을 비밀번호를 입력하여 압축을 풀고
txt 파일을 열어서 확인한다.

```txt
##################################################################################
# Metadium. All Rights Reserved.
# 본 스크립트는 메타디움 testnet 에서 키, META_ID 생성, 메타디움에 등록 및 검증한 결과를 보여줍니다.
# 1. 키 생성(ECDSA secp256k1) (프라이빗키/퍼블릭키)
# 2. META_ID, DID 생성 후 메타디움 블록체인에 등록
# 3. 생성된 퍼블릭키를 메타디움에 등록
# 4. 생성된 DID를 DID Resolver로 검증한 결과
# 5. JWT를 생성된 프라이빗키로 서명하고 메타디움 블록체인에 등록된 퍼블릭키로 검증한 결과
##################################################################################

* 생성일시: 2019-10-14 19:54:25
* 네트워크: testnet

* privateKey: 47440103613447467001763551123532190282719252271057571787261222414024276549651
* privateKeyHex: 68e225a91f5aca2900ec6347163dab9e6a69ba8b203d5a5c2402842cffe5a013
* publicKey: 8482777476442886304371837402654441284418561415629162954994421162679279152011252662806949306010173421193367094402364550005452120261156331019735711720065924
* publicKeyHex: a1f6f3ddb9ce3727f4861a1314b83b52e02a6f11309a1e8a74093d92798125447c5e53b02811479852319ee3b3a55bd63b0ffc905e6aeecfd14aa2607342cb84
* address: 0x76c81ccaed2960ce2a42075adc834caea3f7cf32
* metaId: 0x00000000000000000000000000000000000000000000000000000000000005fb
* META_ID 등록 트랜잭션 해시: 0x04628b1192f222f7455a726bfe3452fcbd7c057a06e86e22214cc13c612689b9
* DID: did:meta:testnet:00000000000000000000000000000000000000000000000000000000000005fb
* DID Resolver URL: https://testnetresolver.metadium.com/1.0/identifiers/did:meta:testnet:00000000000000000000000000000000000000000000000000000000000005fb
* 퍼블릭키 등록 트랜잭션 해시: 0x314e6310a966d7a1a54e4a47bda56f5b2b9c9759b524011efe5c03ca532c4064
* JWT KeyId: did:meta:testnet:00000000000000000000000000000000000000000000000000000000000005fb#MetaManagementKey#76c81ccaed2960ce2a42075adc834caea3f7cf32
* jwk: {"kty":"EC","d":"aOIlqR9ayikA7GNHFj2rnmppuosgPVpcJAKELP_loBM","crv":"P-256K","x":"ofbz3bnONyf0hhoTFLg7UuAqbxEwmh6KdAk9knmBJUQ","y":"fF5TsCgRR5hSMZ7js6Vb1jsP_JBeau7P0UqiYHNCy4Q"}
* 퍼블릭키 등록 검증결과: success
* JWT sign/verify 테스트 결과: success
```

- privateKeyHex : 생성된 EC private key. Hex encoding
- publicKeyHex  : 생성된 EC public key. Hex encoding
- DID : 생성된 DID
- JWT KeyId : Key ID


## WebView 연동 규격

[연규 규격 문서](https://docs.google.com/document/d/1FfpBmz8m3hSPYHaLPsQ0TCVY5NDctjWRuCvxiL3R7AA/edit?usp=sharing)를 확인하시기 바랍니다.


## 사용자 정보 검증

앱에서 AA로 전달한 사용자 정보를 검증하는 예제 코드

```java
/ 앱에서 전달 받은 사용자정보(VerifiablePresentation)
String receiveVP = "...";

// 사용자정보에서 DID 확인
String userDid;
try {
    SignedJWT signedVp = SignedJWT.parse(receiveVP);
    userDid = signedVp.getJWTClaimsSet().getIssuer();
}
catch (ParseException e) {
    // 잘못된 사용자 전달정보
    return;
}

// 사용자 DID 로 검증객체 생성
DidVerifier verifier = new DidVerifier(userDid);

// 사용자정보 검증
if (verifier.extract(receiveVP)) {
	// 추출할 정보 설정
	String presentaionInfoJsonString = ".."; // 앱 등록 시 전달 받은 presentation json 정보
	PresentationInfo presentationInfo = new ObjectMapper().readValue(presentaionInfoJsonString,  PresentationInfo.class);

	// 요청한 데이터를 얻는다. 순서는 PresentationInfo 에 나열된 순서
	try {
		List<ClaimNameValue> claims = verifier.getClaims(presentationInfo, true);

	
		// 사용자의 정보를 획득한다.
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


## 인증서(VerifiableCredentail) 발급

검증에 성공한 사용자 정보를 기반으로 새로운 인증서를 발급한다.  
인증서는 하나의 인증정보(claim) 만 포함할 수 있음.  
여러개의 인증정보를 발급하기 위해서는 여러개의 인증서를 생성해야 하며 아래 과정을 반복을 해야 한다.  

```java
String issuerDid = "did"; // DID 생성 후 발급된 DID 입력
String keyId = "keyId";   // DID 생성 후 발급된 KeyID 입력
ECPrivateKey privateKey = ECKeyUtils.toECPrivateKey(new BigInteger("privateKeyHex", 16), "secp256k1"); // DID 생성 후 생성된 privateKeyHex 값 입력

// VC 생성
VerifiableCredential vc = new VerifiableCredential();
vc.setId(URI.create("http://aa.metadium.com/credential/343"));  // 인증서의 ID 를 설정. 앱에서 해당 URL 로 유효성을 검증한다.
vc.addTypes(Collections.singletonList("NameCredential"));       // Credential 의 이름 설정. 인증서버에 등록한 Credential 이름을 넣는다.
vc.setIssuer(URI.create(issuerDID));                            // AA 의 DID
vc.setIssuanceDate(issuedDate);                                 // 발행 일시
vc.setExpirationDate(expireDate);                               // 만료 일시

// Add claim
LinkedHashMap<String, String> subject = new LinkedHashMap<>();
subject.put("id", "did:meta:0x0000..0011111111120");            // 발행대상자인 사용자의 DID 를 입력 
subject.put("name", "mansud");                                  // claim 정보 입력
vc.setCredentialSubject(subject);

// VC 서명
SignedJWT signedVc = VerifiableSignedJWT.sign(
    verifiableCredential,                                       // verifiable credential
    JWSAlgorithm.ES256K,
    "did:meta:0x348938499420#managementKey#4358",               // key id of signer
    "0d8mf03",                                                  // nonce, 램덤 값으로 생성. 예) UUID.randomUUID().toString()
    new ECDSASigner(privateKey)
);
String signedVcString = signedVc.serialize();                   // 사용자에게 전달할 인증서 값
```



