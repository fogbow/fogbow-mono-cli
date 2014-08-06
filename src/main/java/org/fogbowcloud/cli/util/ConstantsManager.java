package org.fogbowcloud.cli.util;

public class ConstantsManager {

	/**
	 * RequestConstants 
	*/
	// request
	public static final String TERM = "fogbow_request";
	public static final String SCHEME = "http://schemas.fogbowcloud.org/request#";
	public static final String KIND_CLASS = "kind";
	public static final String DEFAULT_TYPE = "one-time";

	// size flavors
	public static final String TEMPLATE_RESOURCE_SCHEME = "http://schemas.fogbowcloud.org/template/resource#";
	public static final String SMALL_TERM = "fogbow_small";

	// image flavors
	public static final String TEMPLATE_OS_SCHEME = "http://schemas.fogbowcloud.org/template/os#";

	// general
	public static final String MIXIN_CLASS = "mixin";
	
	/**
	 * OCCIHeaders.class 
	*/
	// header constants
	public static final String CONTENT_TYPE = "Content-Type";
	public static final String X_AUTH_TOKEN = "X-Auth-Token";

	// occi constants
	public static final String OCCI_CONTENT_TYPE = "text/occi";
	
	/**
	 * Token.class 
	*/	
	public static final String SUBSTITUTE_SPACE_REPLACE = "{!space}";
	public static final String SPACE_REPLACE = " ";
	public static final String SUBSTITUTE_BREAK_LINE_REPLACE = "{!breakline}";
	public static final String BREAK_LINE_REPLACE = "\n";
	
	/**
	 * Token.Constants.class 
	*/
	public enum TokenConstants {
		
		USER_KEY("username"), PASSWORD_KEY("password"), TENANT_ID_KEY("tenantId"), TENANT_NAME_KEY(
				"tenantName"), DATE_EXPIRATION("dataExpiration"), VOMS_PASSWORD("vomsPassword"), VOMS_SERVER_NAME(
				"vomsServerName"), VOMS_PATH_USERCRED("vomsUserCredPath"), VOMS_PATH_USERKEY(
				"vomsUserKeyPath");

		public String value;

		private TokenConstants(String value) {
			this.value = value;
		}			
			
		public String getValue() {
			return value;
		}		
	}
}
