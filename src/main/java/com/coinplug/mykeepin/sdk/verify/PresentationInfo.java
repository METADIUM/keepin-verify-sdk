package com.coinplug.mykeepin.sdk.verify;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * presentation 정보
 * 
 * @author ybjeon
 *
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PresentationInfo {
	/** presentation 이 이름 */
	@JsonProperty("vp")
	public String name;
	
	/** credential 정보 리스트 */
	@JsonProperty("vcs")
	public List<CredentialInfo> credentials;

	/**
	 * credential 정보
	 * 
	 * @author ybjeon
	 *
	 */
	@JsonIgnoreProperties(ignoreUnknown = true)
	public static class CredentialInfo {
		/** credential 발행자의 did */
		@JsonProperty("did")
		public String attestatorAgencyDid;
		
		/** credential 의 이름 */
		@JsonProperty("vc")
		public String name;
		
		/** claim 의 이름 */
		@JsonProperty("name")
		public String claimName;
	}
}
