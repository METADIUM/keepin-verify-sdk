# Keepin SDK Verify for java 

## SDK 소개

## 주요 기능
+ SP 로서 Keepin 앱에 요청한 서명 또는 VP 를 검증
+ Keepin 앱에서 VC 를 발급받기 위해 AA 에게 전달한 VP 검증 및 VC 발급


## SDK 추가


##### Gradle

Add root build.gradle

```gradle
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```

Add dependency

```gradle
// build.gradle
dependencies {
	implementation 'com.github.METADIUM:keepin-verify-sdk:0.2.4'
}
```

##### Maven

Add the JitPack repository to build file

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

아래설정 pom.xml 에 추가

```xml
<!-- pom.xml -->
<dependency>
	<groupId>com.github.METADIUM</groupId>
	<artifactId>keepin-verify-sdk</artifactId>
	<version>0.2.4</version>
</dependency>
```

## Logging

Logging use slf4j.

```xml
<!-- logback.xml -->
<logger name="com.coinplug.mykeepin.sdk.verify" level="DEBUG" additivity ="false">
	<appender-ref ref="console" />
</logger>
```

## ServiceProvider 

[Service Provider 가이드](/sp_guide.md)

## Attestatation Agency
[Attestatation Agency 가이드](/aa_guide.md)

