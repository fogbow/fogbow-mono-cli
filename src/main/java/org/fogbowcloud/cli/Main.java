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
import org.fogbowcloud.manager.occi.OCCIConstants;
import org.fogbowcloud.manager.occi.OCCIConstants.NetworkAllocation;
import org.fogbowcloud.manager.occi.model.HeaderUtils;
import org.fogbowcloud.manager.occi.model.OCCIHeaders;
import org.fogbowcloud.manager.occi.model.Token;
import org.fogbowcloud.manager.occi.order.OrderAttribute;
import org.fogbowcloud.manager.occi.order.OrderConstants;
import org.fogbowcloud.manager.occi.storage.StorageAttribute;
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
	protected static final String DEFAULT_TYPE = OrderConstants.DEFAULT_TYPE;
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
		OrderCommand order = new OrderCommand();
		jc.addCommand("order", order);
		InstanceCommand instance = new InstanceCommand();
		jc.addCommand("instance", instance);
		TokenCommand token = new TokenCommand();
		jc.addCommand("token", token);
		ResourceCommand resource = new ResourceCommand();
		jc.addCommand("resource", resource);
        StorageCommand storage = new StorageCommand();
        jc.addCommand("storage", storage);
        NetworkCommand network = new NetworkCommand();
        jc.addCommand("network", network);        
        AttachmentCommand attachment = new AttachmentCommand();
        jc.addCommand("attachment", attachment);
        AccountingCommand accounting = new AccountingCommand();
        jc.addCommand("accounting", accounting);

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
				if ((!member.quota && !member.usage) || (member.quota && member.usage)) {
					jc.usage();
					return;
				}
				
				if (member.quota) {
					doRequest("get", url + "/member/" + member.memberId + "/quota", federationToken);
				} else if (member.usage) {
					doRequest("get", url + "/member/" + member.memberId + "/usage", federationToken);
				} else {
					jc.usage();
					return;
				}				
			} else {
				doRequest("get", url + "/member", federationToken);				
			}
		} else if (parsedCommand.equals("order")) {
			String url = order.url;
			
			String authToken = normalizeTokenFile(order.authFile);
			if (authToken == null) {
				authToken = normalizeToken(order.authToken);
			}
			
			if (order.get) {
				if (order.create || order.delete) {
					jc.usage();
					return;
				}
				if (order.orderId != null) {
					doRequest("get", url + "/" + OrderConstants.TERM + "/" + order.orderId, authToken);
				} else {
					doRequest("get", url + "/" + OrderConstants.TERM, authToken);
				}
			} else if (order.delete) {
				if (order.create || order.get || order.orderId == null) {
					jc.usage();
					return;
				}
				doRequest("delete", url + "/" + OrderConstants.TERM + "/" + order.orderId, authToken);
			} else if (order.create) {
				if (order.delete || order.get || order.orderId != null) {
					jc.usage();
					return;
				}

				if (!order.type.equals("one-time") && !order.type.equals("persistent")) {
					jc.usage();
					return;
				}
				
				List<Header> headers = new LinkedList<Header>();
				headers.add(new BasicHeader("Category", OrderConstants.TERM + "; scheme=\""
						+ OrderConstants.SCHEME + "\"; class=\"" + OrderConstants.KIND_CLASS
						+ "\""));
				headers.add(new BasicHeader("X-OCCI-Attribute", OrderAttribute.INSTANCE_COUNT
						.getValue() + "=" + order.instanceCount));
				headers.add(new BasicHeader("X-OCCI-Attribute", OrderAttribute.TYPE.getValue()
						+ "=" + order.type));
				
				if (order.resourceKind != null && order.resourceKind.equals(OrderConstants.COMPUTE_TERM)) {
					if (order.flavor != null && !order.flavor.isEmpty()) {
						headers.add(new BasicHeader("Category", order.flavor + "; scheme=\""
								+ OrderConstants.TEMPLATE_RESOURCE_SCHEME + "\"; class=\""
								+ OrderConstants.MIXIN_CLASS + "\""));					
					}
					headers.add(new BasicHeader("Category", order.image + "; scheme=\""
							+ OrderConstants.TEMPLATE_OS_SCHEME + "\"; class=\""
							+ OrderConstants.MIXIN_CLASS + "\""));
					
					if (order.userDataFile != null && !order.userDataFile.isEmpty()) {
						if (order.userDataFileContentType == null 
								|| order.userDataFileContentType.isEmpty()) {
							System.out.println("Content type of user data file cannot be empty.");
							return;
						}
						try {
							String userDataContent = getFileContent(order.userDataFile);
							String userData = userDataContent.replace("\n",
									UserdataUtils.USER_DATA_LINE_BREAKER);
							userData = new String(Base64.encodeBase64(userData.getBytes()));
							headers.add(new BasicHeader("X-OCCI-Attribute", 
									OrderAttribute.EXTRA_USER_DATA_ATT.getValue() + "=" + userData));
							headers.add(new BasicHeader("X-OCCI-Attribute", 
									OrderAttribute.EXTRA_USER_DATA_CONTENT_TYPE_ATT.getValue() 
									+ "=" + order.userDataFileContentType));
						} catch (IOException e) {
							System.out.println("User data file not found.");
							return;
						}
					}
					
					if (order.publicKey != null && !order.publicKey.isEmpty()) {
						
						try {
							order.publicKey = getFileContent(order.publicKey);
						} catch (IOException e) {
							System.out.println("Public key file not found.");
							return;
						}
						
						headers.add(new BasicHeader("Category", OrderConstants.PUBLIC_KEY_TERM
								+ "; scheme=\"" + OrderConstants.CREDENTIALS_RESOURCE_SCHEME
								+ "\"; class=\"" + OrderConstants.MIXIN_CLASS + "\""));
						headers.add(new BasicHeader("X-OCCI-Attribute",
								OrderAttribute.DATA_PUBLIC_KEY.getValue() + "=" + order.publicKey));
					}
					
					if (order.network != null && !order.network.isEmpty()) {
						headers.add(new BasicHeader("Link", "</" + OrderConstants.NETWORK_TERM 
								+ "/" + order.network + ">; rel=\"" + OrderConstants.INFRASTRUCTURE_OCCI_SCHEME 
								+ OrderConstants.NETWORK_TERM + "\"; category=\"" + OrderConstants.INFRASTRUCTURE_OCCI_SCHEME 
								+ OrderConstants.NETWORK_INTERFACE_TERM + "\";"));
					}
						
				} else if (order.resourceKind != null && order.resourceKind.equals(OrderConstants.STORAGE_TERM)) {
					if (order.size != null) {
						headers.add(new BasicHeader("X-OCCI-Attribute", 
								OrderAttribute.STORAGE_SIZE.getValue() + "=" + order.size));						
					} else {
						System.out.println("Size is required when resoure kind is storage");
						return;
					}
				} else if (order.resourceKind != null && order.resourceKind.equals(OrderConstants.NETWORK_TERM)) {
					if (order.cidr != null) {
						headers.add(new BasicHeader("X-OCCI-Attribute", 
								OCCIConstants.NETWORK_ADDRESS + "=" + order.cidr));						
					}
					if (order.gateway != null) {
						headers.add(new BasicHeader("X-OCCI-Attribute", 
								OCCIConstants.NETWORK_GATEWAY + "=" + order.gateway));						
					}				
					if (order.allocation != null) {
						if (!isValidAllocation(order.allocation)) {
							System.out.println("Allocation is not valid. Types allowed : dynamic, static");
							return;							
						}
						headers.add(new BasicHeader("X-OCCI-Attribute", 
								OCCIConstants.NETWORK_ALLOCATION + "=" + order.allocation));						
					}	
				} else {
					System.out.println("Resource Kind is required. Types allowed : compute, storage, network");
					return;
				}
				
				headers.add(new BasicHeader("X-OCCI-Attribute", OrderAttribute.RESOURCE_KIND
						.getValue() + "=" + order.resourceKind));							
				
				if (order.requirements != null) {
					String requirements = Joiner.on(" ").join(order.requirements);
					if (requirements.isEmpty()) {
						System.out.println("Requirements empty.");
						jc.usage();
						return;
					}
					headers.add(new BasicHeader("X-OCCI-Attribute",
							OrderAttribute.REQUIREMENTS.getValue() + "=" + requirements));
				}
				
				doRequest("post", url + "/" + OrderConstants.TERM, authToken, headers);
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
				headers.add(new BasicHeader("Category", OrderConstants.COMPUTE_TERM + "; scheme=\""
						+ OrderConstants.INFRASTRUCTURE_OCCI_SCHEME + "\"; class=\"" + OrderConstants.KIND_CLASS
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
							+ OrderConstants.MIXIN_CLASS + "\""));					
				}
				
				// image
				OCCIElement occiImageEl = OCCIElement.createOCCIEl(instance.image);
				if (occiImageEl == null) {
					jc.usage();
					return;
				}
				
				headers.add(new BasicHeader("Category", occiImageEl.getTerm() + "; scheme=\""
						+ occiImageEl.getScheme() + "\"; class=\""
						+ OrderConstants.MIXIN_CLASS + "\""));
				
				// userdata
				if (instance.userDataFile != null && !instance.userDataFile.isEmpty()) {
					try {
						String userDataContent = getFileContent(instance.userDataFile);
						String userData = userDataContent.replace("\n",
								UserdataUtils.USER_DATA_LINE_BREAKER);
						userData = new String(Base64.encodeBase64(userData.getBytes()));
						
						headers.add(new BasicHeader("Category", "user_data" + "; scheme=\""
								+ "http://schemas.openstack.org/compute/instance#" + "\"; class=\""
								+ OrderConstants.MIXIN_CLASS + "\""));
							
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
							+ OrderConstants.MIXIN_CLASS + "\""));

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
		} else if (parsedCommand.equals("storage")) {
			String url = storage.url;
			
			String authToken = normalizeTokenFile(storage.authFile);
			if (authToken == null) {
				authToken = normalizeToken(storage.authToken);
			}
			
			if (storage.get) {
				if (storage.delete) {
					jc.usage();
					return;							
				}	
				
				if (storage.storageId == null) {
					doRequest("get", url + "/" + OrderConstants.STORAGE_TERM, authToken);
					return;
				} 
				doRequest("get", url + "/" + OrderConstants.STORAGE_TERM + "/" + storage.storageId, authToken);
			} else if (storage.delete) {
				if (storage.get) {
					jc.usage();
					return;							
				}

				if (storage.storageId == null) {
					doRequest("delete", url + "/" + OrderConstants.STORAGE_TERM, authToken);
					return;
				} 
				doRequest("delete", url + "/" + OrderConstants.STORAGE_TERM + "/" + storage.storageId, authToken);
			} else if (storage.create){
				//FIXME: check if the JCommander has a way to set exclusive parameters
				if (storage.delete || storage.get) {
					jc.usage();
					return;							
				}
				
				List<Header> headers = new LinkedList<Header>();
				headers.add(new BasicHeader("Category", OrderConstants.STORAGE_TERM + "; scheme=\""
						+ OrderConstants.INFRASTRUCTURE_OCCI_SCHEME + "\"; class=\"" + OrderConstants.KIND_CLASS
						+ "\""));
				
				if (storage.size == null || storage.size.isEmpty()) {
					jc.usage();
					return;
				}
				
				headers.add(new BasicHeader("X-OCCI-Attribute",
						StorageAttribute.SIZE.getValue() + "=" + storage.size));
				
				doRequest("post", url + "/" + OrderConstants.STORAGE_TERM, authToken, headers);			
			} else {
				jc.usage();
				return;				
			}			
		} else if (parsedCommand.equals("attachment")) {
			String url = attachment.url;
			
			String authToken = normalizeTokenFile(attachment.authFile);
			if (authToken == null) {
				authToken = normalizeToken(attachment.authToken);
			}			
			
			if (attachment.create) {
				if (attachment.delete || attachment.get) {
					jc.usage();
					return;							
				}
				
				List<Header> headers = new LinkedList<Header>();
				headers.add(new BasicHeader("Category", OrderConstants.STORAGELINK_TERM + "; scheme=\""
						+ OrderConstants.INFRASTRUCTURE_OCCI_SCHEME + "\"; class=\"" + OrderConstants.KIND_CLASS
						+ "\""));				
				headers.add(new BasicHeader("X-OCCI-Attribute",
						StorageAttribute.SOURCE.getValue() + "=" + attachment.computeId));
				headers.add(new BasicHeader("X-OCCI-Attribute",
						StorageAttribute.TARGET.getValue() + "=" + attachment.storageId));
				headers.add(new BasicHeader("X-OCCI-Attribute",
						StorageAttribute.DEVICE_ID.getValue() + "=" + attachment.mountPoint));				
				
				doRequest("post", url + "/" + OrderConstants.STORAGE_TERM + "/" 
						+ OrderConstants.STORAGE_LINK_TERM + "/", authToken, headers);				
			} else if (attachment.delete) {
				if (attachment.get || attachment.create) {
					jc.usage();
					return;							
				}

				doRequest("delete", url + "/" + OrderConstants.STORAGE_TERM + "/" 
						+ OrderConstants.STORAGE_LINK_TERM + "/" + attachment.id, authToken);		
			} else if (attachment.get) {
				if (attachment.create || attachment.delete) {
					jc.usage();
					return;							
				}
				
				String endpoint = url + "/" + OrderConstants.STORAGE_TERM + "/" 
						+ OrderConstants.STORAGE_LINK_TERM + "/";
				if (attachment.id != null) {
					endpoint += attachment.id;
				}
				doRequest("get", endpoint , authToken);									
			} else {
				jc.usage();
				return;	
			}			
		} else if (parsedCommand.equals("accounting")) {
			String url = accounting.url;
			
			String authToken = normalizeTokenFile(accounting.authFile);
			if (authToken == null) {
				authToken = normalizeToken(accounting.authToken);
			}			
			
			doRequest("get", url + "/member/accounting", authToken);
		} else if (parsedCommand.equals("network")) {
			String url = network.url;
			
			String authToken = normalizeTokenFile(network.authFile);
			if (authToken == null) {
				authToken = normalizeToken(network.authToken);
			}
			
			if (network.get) {
				if (network.delete || network.create) {
					jc.usage();
					return;							
				}	
				
				if (network.networkId == null) {
					doRequest("get", url + "/" + OrderConstants.NETWORK_TERM + "/", authToken);
					return;
				} 
				doRequest("get", url + "/" + OrderConstants.NETWORK_TERM + "/" + network.networkId, authToken);
			}else if (network.create) {
				if (network.delete || network.get) {
					jc.usage();
					return;							
				}
				
				if (network.cidr == null 
						|| network.gateway == null 
						|| network.allocation == null) {
					jc.usage();
					return;	
				} 
				
				List<Header> headers = new LinkedList<Header>();
				headers.add(new BasicHeader("Category", OrderConstants.NETWORK_TERM + "; scheme=\""
						+ OrderConstants.INFRASTRUCTURE_OCCI_SCHEME + "\"; class=\"" + OrderConstants.KIND_CLASS
						+ "\""));				
				headers.add(new BasicHeader("X-OCCI-Attribute",
						OCCIConstants.NETWORK_ADDRESS + "=" + network.cidr));
				headers.add(new BasicHeader("X-OCCI-Attribute",
						OCCIConstants.NETWORK_GATEWAY + "=" + network.gateway));
				headers.add(new BasicHeader("X-OCCI-Attribute",
						OCCIConstants.NETWORK_ALLOCATION + "=" + network.allocation));	
				
				doRequest("post", url + "/" + OrderConstants.NETWORK_TERM + "/", authToken, headers);
				return;
				
			} else if (network.delete) {
				if (network.get) {
					jc.usage();
					return;							
				}

				if (network.networkId == null) {
					doRequest("delete", url + "/" + OrderConstants.NETWORK_TERM, authToken);
					return;
				} 
				doRequest("delete", url + "/" + OrderConstants.NETWORK_TERM + "/" + network.networkId, authToken);
			} else {
				jc.usage();
				return;				
			}			
		}
	}

	private static boolean isValidAllocation(String allocation) {
		for (NetworkAllocation networkAllocation : OCCIConstants.NetworkAllocation.values()) {
			if (allocation.equals(networkAllocation.getValue())) {
				return true;
			}
		}
		return false;
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
			}
			
			try {
				Token tokenInfo = identityPlugin.getToken(token.token);
				if (token.accessId == false && token.userName == false && token.attributes == false) {
					return tokenInfo.toString();
				}
				
				String responseStr = "";
				if (token.accessId ) {
					responseStr = tokenInfo.getAccessId();
				}
				if (token.userName) {
					if (!responseStr.isEmpty()) {
						responseStr += ",";
					}
					responseStr += tokenInfo.getUser().getName();
				}
				if (token.attributes) {
					if (!responseStr.isEmpty()) {
						responseStr += ",";
					}
					responseStr += tokenInfo.getAttributes();
				}
				
				return responseStr;
			} catch (Exception e) {
				// Do Nothing
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
			if (locationHeader != null && locationHeader.getValue().contains(OrderConstants.TERM)) {
				System.out.println(generateLocationHeaderResponse(locationHeader));
			} else {
				if (method.equals("post")){
					System.out.println(generateLocationHeaderResponse(locationHeader));
				}else{
					System.out.println(EntityUtils.toString(response.getEntity()));
				}
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
	
	@Parameters(separators = "=", commandDescription = "Accounting consult")
	private static class AccountingCommand extends AuthedCommand {
		// There aren't specific commands to this one
	}

	@Parameters(separators = "=", commandDescription = "Order operations")
	private static class OrderCommand extends AuthedCommand {
		@Parameter(names = "--get", description = "Get order")
		Boolean get = false;

		@Parameter(names = "--create", description = "Create order")
		Boolean create = false;

		@Parameter(names = "--delete", description = "Delete order")
		Boolean delete = false;

		@Parameter(names = "--id", description = "Order id")
		String orderId = null;

		@Parameter(names = "--n", description = "Instance count")
		int instanceCount = Main.DEFAULT_INTANCE_COUNT;

		@Parameter(names = "--image", description = "Instance image")
		String image = Main.DEFAULT_IMAGE;

		@Parameter(names = "--flavor", description = "Instance flavor")
		String flavor = null;

		@Parameter(names = "--type", description = "Order type (one-time|persistent)")
		String type = Main.DEFAULT_TYPE;
		
		@Parameter(names = "--public-key", description = "Public key")
		String publicKey = null;
		
		@Parameter(names = "--requirements", description = "Requirements", variableArity = true)
		List<String> requirements = null;
		
		@Parameter(names = "--user-data-file", description = "User data file for cloud init")
		String userDataFile = null;
		
		@Parameter(names = "--user-data-file-content-type", description = "Content type of user data file for cloud init")
		String userDataFileContentType = null;
		
		@Parameter(names = "--size", description = "Size instance storage")
		String size = null;
		
		@Parameter(names = "--resource-kind", description = "Resource kind")
		String resourceKind = null;
		
		@Parameter(names = "--network", description = "Network id")
		String network = null;
		
		@Parameter(names = "--cidr", description = "CIDR")
		String cidr = null;
		
		@Parameter(names = "--gateway", description = "Gateway")
		String gateway = null;
		
		@Parameter(names = "--allocation", description = "Allocation (dynamicy or static)")
		String allocation = null;		
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
	
	@Parameters(separators = "=", commandDescription = "Instance storage operations")
	private static class StorageCommand extends AuthedCommand {
	
		@Parameter(names = "--create", description = "Create instance storage")
		Boolean create = false;

		@Parameter(names = "--get", description = "Get instance storage")
		Boolean get = false;

		@Parameter(names = "--delete", description = "Delete instance storage")
		Boolean delete = false;	

		@Parameter(names = "--id", description = "Instance storage id")
		String storageId = null;
		
		@Parameter(names = "--size", description = "Size instance storage")
		String size = null;		
	}
	
	@Parameters(separators = "=", commandDescription = "Instance network operations")
	private static class NetworkCommand extends AuthedCommand {
		@Parameter(names = "--get", description = "Get instance network")
		Boolean get = false;

		@Parameter(names = "--create", description = "Post new network instance")
		Boolean create = false;
		
		@Parameter(names = "--delete", description = "Delete instance network")
		Boolean delete = false;	

		@Parameter(names = "--id", description = "Instance network id")
		String networkId = null;
		
		@Parameter(names = "--cidr", description = "CIDR")
		String cidr = null;
		
		@Parameter(names = "--gateway", description = "Gateway")
		String gateway = null;
		
		@Parameter(names = "--allocation", description = "Allocation (dynamicy or static)")
		String allocation = null;	
	}	
	
	@Parameters(separators = "=", commandDescription = "Attachment operations")
	private static class AttachmentCommand extends AuthedCommand {
		@Parameter(names = "--create", description = "Attachment create")
		Boolean create = false;
		
		@Parameter(names = "--delete", description = "Attachment delete")
		Boolean delete = false;		

		@Parameter(names = "--get", description = "Get attachment")
		Boolean get = false;	

		@Parameter(names = "--id", description = "Attachment id")
		String id = null;
		
		@Parameter(names = "--storageId", description = "Storage id attribute")
		String storageId = null;
		
		@Parameter(names = "--computeId", description = "Compute id attribute")
		String computeId = null;		
		
		@Parameter(names = "--mountPoint", description = "Mount point attribute")
		String mountPoint = null;				
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
		
		@Parameter(names = "--user", description = "User information")
		boolean userName = false;			
		
		@Parameter(names = "--access-id", description = "Access Id information")
		boolean accessId = false;			
		
		@Parameter(names = "--attributes", description = "Attributes information")
		boolean attributes = false;					
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