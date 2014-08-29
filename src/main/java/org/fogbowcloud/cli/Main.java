package org.fogbowcloud.cli;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

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
import org.fogbowcloud.manager.core.plugins.IdentityPlugin;
import org.fogbowcloud.manager.core.plugins.util.Credential;
import org.fogbowcloud.manager.occi.core.OCCIHeaders;
import org.fogbowcloud.manager.occi.core.Token;
import org.fogbowcloud.manager.occi.request.RequestAttribute;
import org.fogbowcloud.manager.occi.request.RequestConstants;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.util.ClasspathHelper;

import com.beust.jcommander.DynamicParameter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

public class Main {

	protected static final String PLUGIN_PACKAGE = "org.fogbowcloud.manager.core.plugins";
	protected static final String DEFAULT_URL = "http://localhost:8182";
	protected static final int DEFAULT_INTANCE_COUNT = 1;
	protected static final String DEFAULT_TYPE = RequestConstants.DEFAULT_TYPE;
	protected static final String DEFAULT_FLAVOR = RequestConstants.SMALL_TERM;
	protected static final String DEFAULT_IMAGE = "fogbow-linux-x86";

	private static HttpClient client;
	private static IdentityPlugin identityPlugin;

	public static void main(String[] args) throws Exception {
		configureLog4j();
		
		JCommander jc = new JCommander();

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
			doRequest("get", url + "/members", null);
		} else if (parsedCommand.equals("request")) {
			String url = request.url;
			request.authToken = normalizeToken(request.authToken);
			if (request.get) {
				if (request.create || request.delete) {
					jc.usage();
					return;
				}
				if (request.requestId != null) {
					doRequest("get", url + "/" + RequestConstants.TERM + "/" + request.requestId,
							request.authToken);
				} else {
					doRequest("get", url + "/" + RequestConstants.TERM, request.authToken);
				}
			} else if (request.delete) {
				if (request.create || request.get || request.requestId == null) {
					jc.usage();
					return;
				}
				doRequest("delete", url + "/" + RequestConstants.TERM + "/" + request.requestId,
						request.authToken);
			} else if (request.create) {
				if (request.delete || request.get || request.requestId != null) {
					jc.usage();
					return;
				}

				if (!request.type.equals("one-time") && !request.type.equals("persistent")) {
					jc.usage();
					return;
				}

				Set<Header> headers = new HashSet<Header>();
				headers.add(new BasicHeader("Category", RequestConstants.TERM + "; scheme=\""
						+ RequestConstants.SCHEME + "\"; class=\"" + RequestConstants.KIND_CLASS
						+ "\""));
				headers.add(new BasicHeader("X-OCCI-Attribute", RequestAttribute.INSTANCE_COUNT
						.getValue() + "=" + request.instanceCount));
				headers.add(new BasicHeader("X-OCCI-Attribute", RequestAttribute.TYPE.getValue()
						+ "=" + request.type));
				headers.add(new BasicHeader("Category", request.flavor + "; scheme=\""
						+ RequestConstants.TEMPLATE_RESOURCE_SCHEME + "\"; class=\""
						+ RequestConstants.MIXIN_CLASS + "\""));
				headers.add(new BasicHeader("Category", request.image + "; scheme=\""
						+ RequestConstants.TEMPLATE_OS_SCHEME + "\"; class=\""
						+ RequestConstants.MIXIN_CLASS + "\""));
				
				if (request.publicKey != null && !request.publicKey.isEmpty()) {
					headers.add(new BasicHeader("Category", RequestConstants.PUBLIC_KEY_TERM
							+ "; scheme=\"" + RequestConstants.CREDENTIALS_RESOURCE_SCHEME
							+ "\"; class=\"" + RequestConstants.MIXIN_CLASS + "\""));
					headers.add(new BasicHeader("X-OCCI-Attribute",
							RequestAttribute.DATA_PUBLIC_KEY.getValue() + "=" + request.publicKey));
				}
				
				doRequest("post", url + "/" + RequestConstants.TERM, request.authToken, headers);
			}
		} else if (parsedCommand.equals("instance")) {
			String url = instance.url;
			request.authToken = normalizeToken(request.authToken);
			if (instance.delete && instance.get) {
				jc.usage();
				return;
			}
			if (instance.get) {
				if (instance.instanceId != null) {
					doRequest("get", url + "/compute/" + instance.instanceId, instance.authToken);
				} else {
					doRequest("get", url + "/compute/", instance.authToken);
				}
			} else if (instance.delete) {
				if (instance.instanceId == null) {
					jc.usage();
					return;
				}

				doRequest("delete", url + "/compute/" + instance.instanceId, instance.authToken);
			}
		} else if (parsedCommand.equals("token")) {
			System.out.println(createToken(token));
		} else if (parsedCommand.equals("resource")) {
			String url = resource.url;
			String authToken = normalizeToken(resource.authToken);
			doRequest("get", url + "/-/", authToken);
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
			String type = packageName[packageName.length - 1];
			possibleTypes.add(type);
			if (type.equals(token.type)) {
				pluginClass = eachClass;
			}
		}
		
		try {
			if (identityPlugin == null) {
				identityPlugin = (IdentityPlugin) createInstance(pluginClass, new Properties());
			}
		} catch (Exception e) {
			return "Token type [" + token.type + "] is not valid. " + "Possible types: "
					+ possibleTypes + ".";
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

	private static String normalizeToken(String token) {
		if (token == null) {
			return null;
		}
		return token.replace(Token.BREAK_LINE_REPLACE, "");
	}

	private static void doRequest(String method, String endpoint, String authToken)
			throws URISyntaxException, HttpException, IOException {
		doRequest(method, endpoint, authToken, new HashSet<Header>());
	}

	private static void doRequest(String method, String endpoint, String authToken,
			Set<Header> additionalHeaders) throws URISyntaxException, HttpException, IOException {
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

		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
			System.out.println(EntityUtils.toString(response.getEntity()));
		} else {
			System.out.println(response.getStatusLine().toString());
		}
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
		String authToken = System.getenv("FOGBOW_AUTH_TOKEN");
	}

	@Parameters(separators = "=", commandDescription = "Members operations")
	private static class MemberCommand extends Command {
		@Parameter(names = "--get", description = "List federation members")
		Boolean get = true;
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
		String flavor = Main.DEFAULT_FLAVOR;

		@Parameter(names = "--type", description = "Request type (one-time|persistent)")
		String type = Main.DEFAULT_TYPE;
		
		@Parameter(names = "--publicKey", description = "Public key")
		String publicKey = null;
	}

	@Parameters(separators = "=", commandDescription = "Instance operations")
	private static class InstanceCommand extends AuthedCommand {
		@Parameter(names = "--get", description = "Get instance data")
		Boolean get = false;

		@Parameter(names = "--delete", description = "Delete instance")
		Boolean delete = false;

		@Parameter(names = "--id", description = "Instance id")
		String instanceId = null;
	}

	@Parameters(separators = "=", commandDescription = "Token operations")
	protected static class TokenCommand {
		@Parameter(names = "--create", description = "Create token")
		Boolean create = false;

		@Parameter(names = "--type", description = "Token type", required = true)
		String type = null;

		@DynamicParameter(names = "-D", description = "Dynamic parameters")
		Map<String, String> credentials = new HashMap<String, String>();
	}

	@Parameters(separators = "=", commandDescription = "OCCI resources")
	private static class ResourceCommand extends AuthedCommand {
		@Parameter(names = "--get", description = "Get all resources")
		Boolean get = false;
	}
}