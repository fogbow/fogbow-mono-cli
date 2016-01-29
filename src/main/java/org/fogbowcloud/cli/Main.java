package org.fogbowcloud.cli;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.fogbowcloud.manager.core.UserdataUtils;
import org.fogbowcloud.manager.core.plugins.IdentityPlugin;
import org.fogbowcloud.manager.core.plugins.util.Credential;
import org.fogbowcloud.manager.occi.model.HeaderUtils;
import org.fogbowcloud.manager.occi.model.OCCIHeaders;
import org.fogbowcloud.manager.occi.model.Token;
import org.fogbowcloud.manager.occi.request.RequestAttribute;
import org.fogbowcloud.manager.occi.request.RequestConstants;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.util.ClasspathHelper;

import com.beust.jcommander.DynamicParameter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.common.base.Joiner;

@SuppressWarnings("deprecation")
public class Main {

	protected static final String LOCAL_TOKEN_HEADER = "local_token";
	protected static final String PLUGIN_PACKAGE = "org.fogbowcloud.manager.core.plugins.identity";
	protected static final String DEFAULT_URL = "http://localhost:8182";
	protected static final int DEFAULT_INTANCE_COUNT = 1;
	protected static final String DEFAULT_TYPE = RequestConstants.DEFAULT_TYPE;
	protected static final String DEFAULT_IMAGE = "fogbow-linux-x86";

	private static HttpClient client;
	private static IdentityPlugin identityPlugin;

	public static void main(String[] args) throws Exception {
		configureLog4j();

		JCommander jc = new JCommander();
		
		// Normalize args
		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("\"") && args[i].endsWith("\"")) {
				args[i] = args[i].replace("\"", "\"\"");
			}
		}
		
		MemberCommand member = new MemberCommand();
		jc.addCommand("member", member);
		RequestCommand request = new RequestCommand();
		jc.addCommand("request", request);
		InstanceCommand instance = new InstanceCommand();
		jc.addCommand("instance", instance);
		TokenCommand token = new TokenCommand();
		jc.addCommand("token", token);
		ResourceCommand resource = new ResourceCommand();
		jc.addCommand("resource", resource);
        UsageCommand usage = new UsageCommand();
        jc.addCommand("usage", usage);

		jc.setProgramName("fogbow-cli");
		try {
			jc.parse(args);
		} catch (Exception e) {
			System.out.println(e.getMessage());
			jc.usage();
			return;
		}

		String parsedCommand = jc.getParsedCommand();

		if (parsedCommand == null) {
			jc.usage();
			return;
		}

		if (parsedCommand.equals("member")) {	
			String url = member.url;		
			
			String federationToken = normalizeTokenFile(member.authFile);
			if (federationToken == null) {
				federationToken = normalizeToken(member.authToken);
			}
			
			if (member.memberId != null) {
				if (!member.quota) {
					jc.usage();
					return;
				}
				
				doRequest("get", url + "/member/" + member.memberId + "/quota", federationToken);
			} else {
				doRequest("get", url + "/member", federationToken);				
			}
			
		} else if (parsedCommand.equals("request")) {
			String url = request.url;
			
			String authToken = normalizeTokenFile(request.authFile);
			if (authToken == null) {
				authToken = normalizeToken(request.authToken);
			}
			
			if (request.get) {
				if (request.create || request.delete) {
					jc.usage();
					return;
				}
				if (request.requestId != null) {
					doRequest("get", url + "/" + RequestConstants.TERM + "/" + request.requestId, authToken);
				} else {
					doRequest("get", url + "/" + RequestConstants.TERM, authToken);
				}
			} else if (request.delete) {
				if (request.create || request.get || request.requestId == null) {
					jc.usage();
					return;
				}
				doRequest("delete", url + "/" + RequestConstants.TERM + "/" + request.requestId, authToken);
			} else if (request.create) {
				if (request.delete || request.get || request.requestId != null) {
					jc.usage();
					return;
				}

				if (!request.type.equals("one-time") && !request.type.equals("persistent")) {
					jc.usage();
					return;
				}
				
				List<Header> headers = new LinkedList<Header>();
				headers.add(new BasicHeader("Category", RequestConstants.TERM + "; scheme=\""
						+ RequestConstants.SCHEME + "\"; class=\"" + RequestConstants.KIND_CLASS
						+ "\""));
				headers.add(new BasicHeader("X-OCCI-Attribute", RequestAttribute.INSTANCE_COUNT
						.getValue() + "=" + request.instanceCount));
				headers.add(new BasicHeader("X-OCCI-Attribute", RequestAttribute.TYPE.getValue()
						+ "=" + request.type));
				if (request.flavor != null && !request.flavor.isEmpty()) {
					headers.add(new BasicHeader("Category", request.flavor + "; scheme=\""
							+ RequestConstants.TEMPLATE_RESOURCE_SCHEME + "\"; class=\""
							+ RequestConstants.MIXIN_CLASS + "\""));					
				}
				headers.add(new BasicHeader("Category", request.image + "; scheme=\""
						+ RequestConstants.TEMPLATE_OS_SCHEME + "\"; class=\""
						+ RequestConstants.MIXIN_CLASS + "\""));
				
				if (request.userDataFile != null && !request.userDataFile.isEmpty()) {
					if (request.userDataFileContentType == null 
							|| request.userDataFileContentType.isEmpty()) {
						System.out.println("Content type of user data file cannot be empty.");
						return;
					}
					try {
						String userDataContent = getFileContent(request.userDataFile);
						String userData = userDataContent.replace("\n",
								UserdataUtils.USER_DATA_LINE_BREAKER);
						userData = new String(Base64.encodeBase64(userData.getBytes()));
						headers.add(new BasicHeader("X-OCCI-Attribute", 
								RequestAttribute.EXTRA_USER_DATA_ATT.getValue() + "=" + userData));
						headers.add(new BasicHeader("X-OCCI-Attribute", 
								RequestAttribute.EXTRA_USER_DATA_CONTENT_TYPE_ATT.getValue() 
								+ "=" + request.userDataFileContentType));
					} catch (IOException e) {
						System.out.println("User data file not found.");
						return;
					}
				}

				if (request.publicKey != null && !request.publicKey.isEmpty()) {

					try {
						request.publicKey = getFileContent(request.publicKey);
					} catch (IOException e) {
						System.out.println("Public key file not found.");
						return;
					}

					headers.add(new BasicHeader("Category", RequestConstants.PUBLIC_KEY_TERM
							+ "; scheme=\"" + RequestConstants.CREDENTIALS_RESOURCE_SCHEME
							+ "\"; class=\"" + RequestConstants.MIXIN_CLASS + "\""));
					headers.add(new BasicHeader("X-OCCI-Attribute",
							RequestAttribute.DATA_PUBLIC_KEY.getValue() + "=" + request.publicKey));
				}
				
				if (request.requirements != null) {
					String requirements = Joiner.on(" ").join(request.requirements);
					if (requirements.isEmpty()) {
						System.out.println("Requirements empty.");
						jc.usage();
						return;
					}
					headers.add(new BasicHeader("X-OCCI-Attribute",
							"org.fogbowcloud.request.requirements" + "=" + requirements));
				}
				
				doRequest("post", url + "/" + RequestConstants.TERM, authToken, headers);
			}
		} else if (parsedCommand.equals("instance")) {
			String url = instance.url;
			
			String authToken = normalizeTokenFile(instance.authFile);
			if (authToken == null) {
				authToken = normalizeToken(instance.authToken);
			}
			
			if (instance.delete && instance.get) {
				jc.usage();
				return;
			}
			if (instance.get) {
				if (instance.instanceId != null) {
					doRequest("get", url + "/compute/" + instance.instanceId, authToken);
				} else {
					doRequest("get", url + "/compute/", authToken);
				}
			} else if (instance.delete) {
				if (instance.instanceId == null) {
					jc.usage();
					return;
				}

				doRequest("delete", url + "/compute/" + instance.instanceId, authToken);
			} else if (instance.create) {
				if (instance.delete || instance.get || instance.instanceId != null) {
					jc.usage();
					return;
				}
				
				List<Header> headers = new LinkedList<Header>();
				headers.add(new BasicHeader("Category", RequestConstants.COMPUTE_TERM + "; scheme=\""
						+ RequestConstants.INFRASTRUCTURE_OCCI_SCHEME + "\"; class=\"" + RequestConstants.KIND_CLASS
						+ "\""));
								
				// flavor
				if (instance.flavor != null && !instance.flavor.isEmpty()) {
					OCCIElement occiFlavorEl = OCCIElement.createOCCIEl(instance.flavor);
					if (occiFlavorEl == null) {
						jc.usage();
						return;
					}
					
					headers.add(new BasicHeader("Category", occiFlavorEl.getTerm() + "; scheme=\""
							+ occiFlavorEl.getScheme() + "\"; class=\""
							+ RequestConstants.MIXIN_CLASS + "\""));					
				}
				
				// image
				OCCIElement occiImageEl = OCCIElement.createOCCIEl(instance.image);
				if (occiImageEl == null) {
					jc.usage();
					return;
				}
				
				headers.add(new BasicHeader("Category", occiImageEl.getTerm() + "; scheme=\""
						+ occiImageEl.getScheme() + "\"; class=\""
						+ RequestConstants.MIXIN_CLASS + "\""));
				
				// userdata
				if (instance.userDataFile != null && !instance.userDataFile.isEmpty()) {
					try {
						String userDataContent = getFileContent(instance.userDataFile);
						String userData = userDataContent.replace("\n",
								UserdataUtils.USER_DATA_LINE_BREAKER);
						userData = new String(Base64.encodeBase64(userData.getBytes()));
						
						headers.add(new BasicHeader("Category", "user_data" + "; scheme=\""
								+ "http://schemas.openstack.org/compute/instance#" + "\"; class=\""
								+ RequestConstants.MIXIN_CLASS + "\""));
							
						headers.add(new BasicHeader("X-OCCI-Attribute", 
								"org.openstack.compute.user_data=" + userData));						
					} catch (IOException e) {
						System.out.println("User data file not found.");
						return;
					}
				}

				// publickey
				if (instance.publicKey != null && !instance.publicKey.isEmpty()) {

					try {
						instance.publicKey = getFileContent(instance.publicKey);
					} catch (IOException e) {
						System.out.println("Public key file not found.");
						return;
					}
					
					headers.add(new BasicHeader("Category", "public_key" + "; scheme=\""
							+ "http://schemas.openstack.org/instance/credentials#" + "\"; class=\""
							+ RequestConstants.MIXIN_CLASS + "\""));

					headers.add(new BasicHeader("X-OCCI-Attribute",
							"org.openstack.credentials.publickey.data=" + instance.publicKey));
					headers.add(new BasicHeader("X-OCCI-Attribute",
							"org.openstack.credentials.publickey.name=fogbow"));
				}
				doRequest("post", url + "/compute/", authToken, headers);
			}
		} else if (parsedCommand.equals("token")) {
			if (token.check) {
				System.out.println(checkToken(token));
			} else if (token.info) {
				System.out.println(getTokenInfo(token));
			} else {
				System.out.println(createToken(token));							
			}
		} else if (parsedCommand.equals("resource")) {
			String url = resource.url;
			
			String authToken = normalizeTokenFile(resource.authFile);
			if (authToken == null) {
				authToken = normalizeToken(resource.authToken);
			}
						
			doRequest("get", url + "/-/", authToken);
		} else if (parsedCommand.equals("usage")) {
			String url = usage.url;
			
			String authToken = normalizeTokenFile(usage.authFile);
			if (authToken == null) {
				authToken = normalizeToken(usage.authToken);
			}
			
			if (!usage.members && !usage.users) {
				jc.usage();
				return;
			}
			
			if (usage.members && usage.users) {
				doRequest("get", url + "/usage", authToken);
			} else if (usage.members) {
				doRequest("get", url + "/usage/members", authToken);
			} else if (usage.users) {
				doRequest("get", url + "/usage/users", authToken);
			} else {
				jc.usage();
				return;
			}
		}
	}
	
	private static void configureLog4j() {
		ConsoleAppender console = new ConsoleAppender();
		console.setThreshold(Level.OFF);
		console.activateOptions();
		Logger.getRootLogger().addAppender(console);
	}

	public static void setIdentityPlugin(IdentityPlugin identityPlugin) {
		Main.identityPlugin = identityPlugin;
	}
	
	public static IdentityPlugin getIdentityPlugin() {
		return identityPlugin;
	}
	
	@SuppressWarnings("resource")
	private static String getFileContent(String path) throws IOException {		
		FileReader reader = new FileReader(path);
		BufferedReader leitor = new BufferedReader(reader);
		String fileContent = "";
		String linha = "";
		while (true) {
			linha = leitor.readLine();
			if (linha == null)
				break;
			fileContent += linha + "\n";
		}
		return fileContent.trim();
	}
		
	protected static String getTokenInfo(TokenCommand token) {
		Reflections reflections = new Reflections(
				ClasspathHelper.forPackage(PLUGIN_PACKAGE), 
		        new SubTypesScanner());
		
		Set<Class<? extends IdentityPlugin>> allClasses = reflections
				.getSubTypesOf(IdentityPlugin.class);
		Class<?> pluginClass = null;
		List<String> possibleTypes = new LinkedList<String>();
		for (Class<? extends IdentityPlugin> eachClass : allClasses) {
			String[] packageName = eachClass.getName().split("\\.");
			String type = packageName[packageName.length - 2];
			possibleTypes.add(type);
			if (type.equals(token.type)) {
				pluginClass = eachClass;
			}
		}
		
		try {
			if (identityPlugin == null) {
				Map<String, String> credentials = token.credentials;			
				Properties properties = new Properties();
				for (Entry<String, String> credEntry : credentials.entrySet()) {
					properties.put(credEntry.getKey(), credEntry.getValue());
				}
				identityPlugin = (IdentityPlugin) createInstance(pluginClass, properties);
				try {
					Token tokenInfo = identityPlugin.getToken(token.token);
					return tokenInfo.toString();					
				} catch (Exception e) {
					// Do Nothing
				}
			}
		} catch (Exception e) {
			return "Token type [" + token.type + "] is not valid. " + "Possible types: "
					+ possibleTypes + ".";
		}	
		return "No Result.";
	}
	
	protected static String checkToken(TokenCommand token) {
		Reflections reflections = new Reflections(
				ClasspathHelper.forPackage(PLUGIN_PACKAGE), 
		        new SubTypesScanner());
		
		Set<Class<? extends IdentityPlugin>> allClasses = reflections
				.getSubTypesOf(IdentityPlugin.class);
		Class<?> pluginClass = null;
		List<String> possibleTypes = new LinkedList<String>();
		for (Class<? extends IdentityPlugin> eachClass : allClasses) {
			String[] packageName = eachClass.getName().split("\\.");
			String type = packageName[packageName.length - 2];
			possibleTypes.add(type);
			if (type.equals(token.type)) {
				pluginClass = eachClass;
			}
		}
		
		try {
			if (identityPlugin == null) {
				Map<String, String> credentials = token.credentials;			
				Properties properties = new Properties();
				for (Entry<String, String> credEntry : credentials.entrySet()) {
					properties.put(credEntry.getKey(), credEntry.getValue());
				}
				identityPlugin = (IdentityPlugin) createInstance(pluginClass, properties);
			}
		} catch (Exception e) {
			return "Token type [" + token.type + "] is not valid. " + "Possible types: "
					+ possibleTypes + ".";
		}
		
		try {
			boolean isValid = identityPlugin.isValid(token.token);
			if (isValid) {
				return "Token Valid";
			} else {
				return "Token Unauthorized";
			}
		} catch (Exception e) {
			return "Token Unauthorized";
		}	
	}
	
	protected static String createToken(TokenCommand token) {
		Reflections reflections = new Reflections(
				ClasspathHelper.forPackage(PLUGIN_PACKAGE), 
		        new SubTypesScanner());
		
		Set<Class<? extends IdentityPlugin>> allClasses = reflections
				.getSubTypesOf(IdentityPlugin.class);
		Class<?> pluginClass = null;
		List<String> possibleTypes = new LinkedList<String>();
		for (Class<? extends IdentityPlugin> eachClass : allClasses) {
			String[] packageName = eachClass.getName().split("\\.");
			String type = packageName[packageName.length - 2];
			possibleTypes.add(type);
			if (type.equals(token.type)) {
				pluginClass = eachClass;
			}
		}
		
		if (pluginClass == null) {
			return "Token type [" + token.type + "] is not valid. " + "Possible types: "
					+ possibleTypes + ".";
		}
		
		try {
			if (identityPlugin == null) {
				identityPlugin = (IdentityPlugin) createInstance(pluginClass, new Properties());
			}
		} catch (Exception e) {
			return e.getMessage() + "\n" + getPluginCredentialsInformation(allClasses);
		}

		try {
			return generateResponse(identityPlugin.createToken(token.credentials));
		} catch (Exception e) {
			return e.getMessage() + "\n" + getPluginCredentialsInformation(allClasses);
		}
	}
	
	protected static String getPluginCredentialsInformation(
			Set<Class<? extends IdentityPlugin>> allClasses) {
		StringBuilder response = new StringBuilder();
		response.append("Credentials :\n");
		for (Class<? extends IdentityPlugin> eachClass : allClasses) {
			String[] identityPluginFullName = eachClass.getName().split("\\.");
			System.out.println(eachClass.getName());
			IdentityPlugin identityPlugin = null;
			try {
				identityPlugin = (IdentityPlugin) createInstance(eachClass, new Properties());
			} catch (Exception e) {
			}
			if (identityPlugin.getCredentials() == null) {
				continue;
			}
			response.append("* " + identityPluginFullName[identityPluginFullName.length - 1] + "\n");
			for (Credential credential : identityPlugin.getCredentials()) {
				String valueDefault = "";
				if (credential.getValueDefault() != null) {
					valueDefault = " - default :" + credential.getValueDefault();
				}
				String feature = "Optional";
				if (credential.isRequired()) {
					feature = "Required";
				}
				response.append("   -D" + credential.getName() + " (" + feature + ")"
						+ valueDefault + "\n");
			}
		}
		return response.toString().trim();
	}

	private static String generateResponse(Token token) {
		if (token == null) {
			return new String();
		}
		return token.getAccessId();
	}

	protected static Object createInstance(Class<?> pluginClass, Properties properties)
			throws Exception {
		return pluginClass.getConstructor(Properties.class).newInstance(properties);
	}

	protected static String normalizeToken(String token) {
		if (token == null) {
			return null;
		}				
		return token.replace("\n", "");
	}
	
	protected static String normalizeTokenFile(String token) {
		if (token == null) {
			return null;
		}		
		File tokenFile = new File(token);
		if (tokenFile.exists()) {
			try {
				token = IOUtils.toString(new FileInputStream(tokenFile));
			} catch (Exception e) {
				return null;
			}
		} else {
			return null;
		}		
		return token.replace("\n", "");
	}	

	private static void doRequest(String method, String endpoint, String authToken) throws URISyntaxException, HttpException, IOException {
		doRequest(method, endpoint, authToken, new LinkedList<Header>());
	}

	private static void doRequest(String method, String endpoint, String authToken, 
			List<Header> additionalHeaders) throws URISyntaxException, HttpException, IOException {
		HttpUriRequest request = null;
		if (method.equals("get")) {
			request = new HttpGet(endpoint);
		} else if (method.equals("delete")) {
			request = new HttpDelete(endpoint);
		} else if (method.equals("post")) {
			request = new HttpPost(endpoint);
		}
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		if (authToken != null) {
			request.addHeader(OCCIHeaders.X_AUTH_TOKEN, authToken);
		}
		for (Header header : additionalHeaders) {
			request.addHeader(header);
		}
		
		if (client == null) {
			client = new DefaultHttpClient();
			HttpParams params = new BasicHttpParams();
			params.setParameter(CoreProtocolPNames.PROTOCOL_VERSION, HttpVersion.HTTP_1_1);
			client = new DefaultHttpClient(new ThreadSafeClientConnManager(params, client
					.getConnectionManager().getSchemeRegistry()), params);
		}

		HttpResponse response = client.execute(request);

		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK
				|| response.getStatusLine().getStatusCode() == HttpStatus.SC_CREATED) {
			Header locationHeader = getLocationHeader(response.getAllHeaders());
			if (locationHeader != null && locationHeader.getValue().contains(RequestConstants.TERM)) {
				System.out.println(generateLocationHeaderResponse(locationHeader));
			} else {
				System.out.println(EntityUtils.toString(response.getEntity()));
			}
		} else {
			System.out.println(response.getStatusLine().toString());
		}
	}	
	
	protected static Header getLocationHeader(Header[] headers) {
		Header locationHeader = null;
		for (Header header : headers) {	
			if (header.getName().equals("Location")) {
				locationHeader = header;
			}
		}
		return locationHeader;
	}
	
	protected static String generateLocationHeaderResponse(Header header) {
		String[] locations = header.getValue().split(",");
		String response = "";
		for (String location : locations) {
			response += HeaderUtils.X_OCCI_LOCATION_PREFIX + location + "\n";
		}
		return response.trim();
	}

	public static void setClient(HttpClient client) {
		Main.client = client;
	}

	private static class Command {
		@Parameter(names = "--url", description = "fogbow manager url")
		String url = System.getenv("FOGBOW_URL") == null ? Main.DEFAULT_URL : System
				.getenv("FOGBOW_URL");
	}

	private static class AuthedCommand extends Command {
		@Parameter(names = "--auth-token", description = "auth token")
		String authToken = null;
		
		@Parameter(names = "--auth-file", description = "auth file")
		String authFile = null;
	}

	@Parameters(separators = "=", commandDescription = "Members operations")
	private static class MemberCommand extends AuthedCommand {
		@Parameter(names = "--quota", description = "Quota")
		Boolean quota = false;
		
		@Parameter(names = "--id", description = "Member Id")
		String memberId = null;
					
		@Parameter(names = "--usage", description = "Usage")
		Boolean usage = false;		
	}
	
	@Parameters(separators = "=", commandDescription = "Usage consults")
	private static class UsageCommand extends AuthedCommand {
		@Parameter(names = "--members", description = "List members' usage")
		Boolean members = false;

		@Parameter(names = "--users", description = "List users' usage")
		Boolean users = false;
	}

	@Parameters(separators = "=", commandDescription = "Request operations")
	private static class RequestCommand extends AuthedCommand {
		@Parameter(names = "--get", description = "Get request")
		Boolean get = false;

		@Parameter(names = "--create", description = "Create request")
		Boolean create = false;

		@Parameter(names = "--delete", description = "Delete request")
		Boolean delete = false;

		@Parameter(names = "--id", description = "Request id")
		String requestId = null;

		@Parameter(names = "--n", description = "Instance count")
		int instanceCount = Main.DEFAULT_INTANCE_COUNT;

		@Parameter(names = "--image", description = "Instance image")
		String image = Main.DEFAULT_IMAGE;

		@Parameter(names = "--flavor", description = "Instance flavor")
		String flavor = null;

		@Parameter(names = "--type", description = "Request type (one-time|persistent)")
		String type = Main.DEFAULT_TYPE;
		
		@Parameter(names = "--public-key", description = "Public key")
		String publicKey = null;
		
		@Parameter(names = "--requirements", description = "Requirements", variableArity = true)
		List<String> requirements = null;
		
		@Parameter(names = "--user-data-file", description = "User data file for cloud init")
		String userDataFile = null;
		
		@Parameter(names = "--user-data-file-content-type", description = "Content type of user data file for cloud init")
		String userDataFileContentType = null;
	}

	@Parameters(separators = "=", commandDescription = "Instance operations")
	private static class InstanceCommand extends AuthedCommand {
		@Parameter(names = "--get", description = "Get instance data")
		Boolean get = false;

		@Parameter(names = "--delete", description = "Delete instance")
		Boolean delete = false;
		
		@Parameter(names = "--create", description = "Create instance directly")
		Boolean create = false;

		@Parameter(names = "--id", description = "Instance id")
		String instanceId = null;
		
		@Parameter(names = "--flavor", description = "Instance flavor")
		String flavor = null;
		
		@Parameter(names = "--image", description = "Instance image")
		String image = null;
		
		@Parameter(names = "--user-data-file", description = "User data file for cloud init")
		String userDataFile = null;
		
		@Parameter(names = "--public-key", description = "Public key")
		String publicKey = null;
	}

	@Parameters(separators = "=", commandDescription = "Token operations")
	protected static class TokenCommand {
		@Parameter(names = "--create", description = "Create token")
		Boolean create = false;

		@Parameter(names = "--type", description = "Token type")
		String type = null;

		@DynamicParameter(names = "-D", description = "Dynamic parameters")
		Map<String, String> credentials = new HashMap<String, String>();
		
		@Parameter(names = "--check", description = "Check token")
		Boolean check = false;
				
		@Parameter(names = "--info", description = "Get Info")
		Boolean info = false;
		
		@Parameter(names = "--token", description = "Token Pure")
		String token = null;			
	}

	@Parameters(separators = "=", commandDescription = "OCCI resources")
	private static class ResourceCommand extends AuthedCommand {
		@Parameter(names = "--get", description = "Get all resources")
		Boolean get = false;
	}
	
	private static class OCCIElement {

		private String term;
		private String scheme;
		
		private OCCIElement(String scheme, String term) {
			this.term = term;
			this.scheme = scheme;
		}
		
		public static OCCIElement createOCCIEl(String occiElStr) {
			int hashIndex = occiElStr.indexOf('#');
			return new OCCIElement(occiElStr.substring(0, hashIndex + 1), occiElStr.substring(hashIndex + 1));
		}

		public String getScheme() {
			return this.scheme;
		}

		public String getTerm() {
			return this.term;
		}
	}

}