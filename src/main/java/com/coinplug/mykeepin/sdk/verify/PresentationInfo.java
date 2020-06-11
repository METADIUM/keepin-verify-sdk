package com.coinplug.mykeepin.sdk.verify;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;

/**
 * presentation 정보
 * 
 * @author ybjeon
 *
 */
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
		
		/** claim 값의 type. int, long, String, float, double, boolean. */
		public Class<?> claimValueClass;
		
		@JsonSetter("type")
		public void setClaimValue(String type) {
			if (type == null) {
				return;
			}
			
			if (type.equalsIgnoreCase("int") || type.equals("Integer")) {
				this.claimValueClass = Integer.class;
			}
			else if (type.equalsIgnoreCase("long") || type.equals("Long")) {
				this.claimValueClass = Long.class;
			}
			else if (type.equalsIgnoreCase("float")) {
				this.claimValueClass = Float.class;
			}
			else if (type.equalsIgnoreCase("double")) {
				this.claimValueClass = Double.class;
			}
			else if (type.equalsIgnoreCase("bool") || type.equalsIgnoreCase("boolean")) {
				this.claimValueClass = Boolean.class;
			}
			else if (type.equalsIgnoreCase("String")) {
				this.claimValueClass = String.class;
			}
		}
	}
}
