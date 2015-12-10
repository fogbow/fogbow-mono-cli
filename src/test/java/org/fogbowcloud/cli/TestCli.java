package org.fogbowcloud.cli;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseFactory;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicStatusLine;
import org.fogbowcloud.cli.Main.TokenCommand;
import org.fogbowcloud.manager.core.plugins.IdentityPlugin;
import org.fogbowcloud.manager.core.plugins.util.Credential;
import org.fogbowcloud.manager.occi.model.HeaderUtils;
import org.fogbowcloud.manager.occi.model.OCCIHeaders;
import org.fogbowcloud.manager.occi.model.Token;
import org.fogbowcloud.manager.occi.request.RequestAttribute;
import org.fogbowcloud.manager.occi.request.RequestConstants;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.util.ClasspathHelper;

public class TestCli {

	private final String REQUEST_ID = "234GD0-43254435-4543T4";
	private static final String ACCESS_TOKEN_ID = "accesstoken";
	private static final String INSTANCE_ID = "instanceid";

	private Main cli;
	private HttpClient client;
	private HttpUriRequestMatcher expectedRequest;

	@SuppressWarnings("static-access")
	@Before
	public void setUp() throws Exception {
		cli = new Main();
		client = Mockito.mock(HttpClient.class);
		HttpResponseFactory factory = new DefaultHttpResponseFactory();
		HttpResponse response = factory.newHttpResponse(new BasicStatusLine(HttpVersion.HTTP_1_1,
				HttpStatus.SC_NO_CONTENT, "Return Irrelevant"), null);
		Mockito.when(client.execute(Mockito.any(HttpUriRequest.class))).thenReturn(response);
		cli.setClient(client);

	}	

	@SuppressWarnings({ "static-access", "unchecked" })
	@Test
	public void commandGetToken() throws Exception {
		IdentityPlugin identityPlugin = Mockito.mock(IdentityPlugin.class);
		String accessId = "AccessId";
		Token token = new Token(accessId , "user", null, null);
		Mockito.when(identityPlugin.createToken(Mockito.anyMap())).thenReturn(token);
		
		TokenCommand tokenCommand = new TokenCommand();
		tokenCommand.type = "openstack";
		tokenCommand.credentials = new HashMap<String, String>();	
	
		cli.setIdentityPlugin(identityPlugin);
		Assert.assertEquals(accessId, cli.createToken(tokenCommand));
	}
	
	@SuppressWarnings("static-access")
	@Test
	public void commandWithoutUrl() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/compute/");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "instance --get --auth-token "
				+ ACCESS_TOKEN_ID;
		cli.main(createArgs(command));
			
		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandPostRequest() throws Exception {
		final String intanceCount = "2";
		final String image = "image";
		final String flavor = "flavor";
		final String requirements = "X>=1&&Y=2";

		HttpUriRequest request = new HttpPost(Main.DEFAULT_URL + "/" + RequestConstants.TERM);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader("Category", RequestConstants.TERM
				+ "; scheme=\"http://schemas.fogbowcloud.org/request#\"; class=\"kind\"");
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.instance-count="
				+ intanceCount);
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.type=one-time");
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.requirements=" + requirements);
		request.addHeader("Category", flavor
				+ "; scheme=\"http://schemas.fogbowcloud.org/template/resource#\"; class=\"mixin\"");
		request.addHeader("Category", image
				+ "; scheme=\"http://schemas.fogbowcloud.org/template/os#\"; class=\"mixin\"");
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "request --create --n " + intanceCount + " --url " + Main.DEFAULT_URL
				+ " " + "--image " + image + " --auth-token " + ACCESS_TOKEN_ID
				+ " --requirements " + requirements + " --flavor " + flavor;

		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}
	
	@SuppressWarnings("static-access")
	@Test
	public void commandPostRequestWithDataUser() throws Exception {
		final String intanceCount = "2";
		final String image = "image";
		final String flavor = "flavor";
		final String requirements = "X>=1&&Y=2";
		String userDataPath = "src/test/resource/get_content";
		String userDataContent = "";
		File file = new File(userDataPath);
		userDataContent = IOUtils.toString(new FileInputStream(file));
		String type = "Maaarcos";

		HttpUriRequest request = new HttpPost(Main.DEFAULT_URL + "/" + RequestConstants.TERM);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader("Category", RequestConstants.TERM
				+ "; scheme=\"http://schemas.fogbowcloud.org/request#\"; class=\"kind\"");
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.instance-count="
				+ intanceCount);
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.type=one-time");
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.requirements=" + requirements);
		request.addHeader("X-OCCI-Attribute", RequestAttribute.EXTRA_USER_DATA_ATT.getValue() + "="
				+ new String(Base64.encodeBase64(userDataContent.getBytes())));
		request.addHeader("X-OCCI-Attribute", RequestAttribute.EXTRA_USER_DATA_CONTENT_TYPE_ATT.getValue() + "=" + type);		
		request.addHeader("Category", flavor
				+ "; scheme=\"http://schemas.fogbowcloud.org/template/resource#\"; class=\"mixin\"");
		request.addHeader("Category", image
				+ "; scheme=\"http://schemas.fogbowcloud.org/template/os#\"; class=\"mixin\"");
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "request --create --n " + intanceCount + " --url " + Main.DEFAULT_URL
				+ " " + "--image " + image + " --auth-token " + ACCESS_TOKEN_ID
				+ " --requirements " + requirements + " --flavor " + flavor + " --user-data-file " + userDataPath
				+ " --user-data-file-content-type " + type;

		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}	
	
	@SuppressWarnings("static-access")
	@Test
	public void commandPostRequestWithoutRequirements() throws Exception {
		final String intanceCount = "2";
		final String image = "image";
		final String flavor = "flavor";

		HttpUriRequest request = new HttpPost(Main.DEFAULT_URL + "/" + RequestConstants.TERM);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader("Category", RequestConstants.TERM
				+ "; scheme=\"http://schemas.fogbowcloud.org/request#\"; class=\"kind\"");
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.instance-count="
				+ intanceCount);
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.type=one-time");
		request.addHeader("Category", flavor
				+ "; scheme=\"http://schemas.fogbowcloud.org/template/resource#\"; class=\"mixin\"");
		request.addHeader("Category", image
				+ "; scheme=\"http://schemas.fogbowcloud.org/template/os#\"; class=\"mixin\"");
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "request --create --n " + intanceCount + " --url " + Main.DEFAULT_URL
				+ " " + "--image " + image + " --auth-token " + ACCESS_TOKEN_ID
				+ " --flavor " + flavor;
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}
	
	@SuppressWarnings("static-access")
	@Test
	public void commandPostRequestDefaultValues() throws Exception {
		String requirements = "X1==&&Y==2";
		
		HttpUriRequest request = new HttpPost(Main.DEFAULT_URL + "/" + RequestConstants.TERM);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader("Category", RequestConstants.TERM + "; scheme=\""
				+ RequestConstants.SCHEME + "\"; class=\"" + RequestConstants.KIND_CLASS + "\"");
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.instance-count="
				+ Main.DEFAULT_INTANCE_COUNT);
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.type=one-time");
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.requirements=" + requirements);
		request.addHeader("Category", Main.DEFAULT_IMAGE + "; scheme=\""
				+ RequestConstants.TEMPLATE_OS_SCHEME + "\"; class=\""
				+ RequestConstants.MIXIN_CLASS + "\"");
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "request --create --url " + Main.DEFAULT_URL + " --auth-token "
				+ ACCESS_TOKEN_ID + " --requirements " + requirements;

		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandGetSpecificRequest() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/" + RequestConstants.TERM + "/"
				+ REQUEST_ID);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);

		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "request --get --url " + Main.DEFAULT_URL + " --auth-token "
				+ ACCESS_TOKEN_ID + " --id " + REQUEST_ID;
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandGetRequest() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/" + RequestConstants.TERM);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);

		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "request --get --url " + Main.DEFAULT_URL + " --auth-token "
				+ ACCESS_TOKEN_ID;
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandDeleteRequest() throws Exception {
		HttpUriRequest request = new HttpDelete(Main.DEFAULT_URL + "/" + RequestConstants.TERM
				+ "/" + REQUEST_ID);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);

		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "request --delete --url " + Main.DEFAULT_URL + " --auth-token "
				+ ACCESS_TOKEN_ID + " --id " + REQUEST_ID;
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandGetQuery() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/-/");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "resource --get";
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandGetMember() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/members");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "member --get" + " --federation-auth-token " + ACCESS_TOKEN_ID;
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandCreateInstance() throws Exception {
		HttpUriRequest request = new HttpPost(Main.DEFAULT_URL + "/compute/");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		request.addHeader("Category", RequestConstants.COMPUTE_TERM + "; scheme=\""
				+ RequestConstants.INFRASTRUCTURE_OCCI_SCHEME + "\"; class=\""
				+ RequestConstants.KIND_CLASS + "\"");
		request.addHeader("Category",
				"large; scheme=\"http://schemas.openstack.org/template/resource#\"; class=\""
						+ RequestConstants.MIXIN_CLASS + "\"");
		request.addHeader("Category",
				"imageName; scheme=\"http://schemas.openstack.org/template/os#\"; class=\""
						+ RequestConstants.MIXIN_CLASS + "\"");
		
		expectedRequest = new HttpUriRequestMatcher(request);

		String flavorId = "http://schemas.openstack.org/template/resource#large";		
		String imageId = "http://schemas.openstack.org/template/os#imageName";
		
		String command = "instance --create --url " + Main.DEFAULT_URL + " " + " --auth-token "
				+ ACCESS_TOKEN_ID + " --image " + imageId + " --flavor " +  flavorId;
		
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}
	
	@SuppressWarnings("static-access")
	@Test
	public void commandCreateInstanceWithUserData() throws Exception {
		String userDataPath = "src/test/resource/get_content";
		String userDataContent = "";
		File file = new File(userDataPath);
		userDataContent = IOUtils.toString(new FileInputStream(file));
		
		HttpUriRequest request = new HttpPost(Main.DEFAULT_URL + "/compute/");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		request.addHeader("Category", RequestConstants.COMPUTE_TERM + "; scheme=\""
				+ RequestConstants.INFRASTRUCTURE_OCCI_SCHEME + "\"; class=\""
				+ RequestConstants.KIND_CLASS + "\"");
		request.addHeader("Category",
				"large; scheme=\"http://schemas.openstack.org/template/resource#\"; class=\""
						+ RequestConstants.MIXIN_CLASS + "\"");
		request.addHeader("Category",
				"imageName; scheme=\"http://schemas.openstack.org/template/os#\"; class=\""
						+ RequestConstants.MIXIN_CLASS + "\"");
		request.addHeader("Category", "user_data" + "; scheme=\""
				+ "http://schemas.openstack.org/compute/instance#" + "\"; class=\""
				+ RequestConstants.MIXIN_CLASS + "\"");
		request.addHeader("X-OCCI-Attribute", "org.openstack.compute.user_data=" + new String(Base64.encodeBase64(userDataContent.getBytes())));
				
		expectedRequest = new HttpUriRequestMatcher(request);

		String flavorId = "http://schemas.openstack.org/template/resource#large";		
		String imageId = "http://schemas.openstack.org/template/os#imageName";
		
		String command = "instance --create --url " + Main.DEFAULT_URL + " " + " --auth-token "
				+ ACCESS_TOKEN_ID + " --image " + imageId + " --flavor " +  flavorId + " --user-data-file " + userDataPath;
		
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}
	
	@SuppressWarnings("static-access")
	@Test
	public void commandGetInstance() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/compute/");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "instance --get --url " + Main.DEFAULT_URL + " " + " --auth-token "
				+ ACCESS_TOKEN_ID;
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandGetSpecificInstance() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/compute/" + INSTANCE_ID);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "instance --get --url " + Main.DEFAULT_URL + " " + "--id " + INSTANCE_ID
				+ " --auth-token " + ACCESS_TOKEN_ID;
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandDeleteInstance() throws Exception {
		HttpUriRequest request = new HttpDelete(Main.DEFAULT_URL + "/compute/" + INSTANCE_ID);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "instance --delete --url " + Main.DEFAULT_URL + " " + "--id "
				+ INSTANCE_ID + " --auth-token " + ACCESS_TOKEN_ID;

		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}
	
	@SuppressWarnings("static-access")
	@Test
	public void testGetCredentialsInformation() {
		Reflections reflections = new Reflections(ClasspathHelper.forPackage(Main.PLUGIN_PACKAGE),
				new SubTypesScanner());

		Set<Class<? extends IdentityPlugin>> allClasses = reflections
				.getSubTypesOf(IdentityPlugin.class);

		String response = cli.getPluginCredentialsInformation(allClasses);

		for (Class<? extends IdentityPlugin> eachClass : allClasses) {
			IdentityPlugin identityPlugin = null;
			try {
				identityPlugin = (IdentityPlugin) cli.createInstance(eachClass, new Properties());
				for (Credential credential : identityPlugin.getCredentials()) {
					Assert.assertTrue(response.contains(credential.getName()));
					if (credential.getValueDefault() != null) {
						Assert.assertTrue(response.contains(credential.getValueDefault()));
					}
				}
			} catch (Exception e) {
			}
		}

	}

	@Test
	public void testGetLocationHeader() {
		Header[] headers = new Header[3];
		String responseOk = "OK";
		headers[0] = new BasicHeader("Location", responseOk);
		headers[1] = new BasicHeader("Test1", "");
		headers[2] = new BasicHeader("Test2", "");
		Header locationHeader = Main.getLocationHeader(headers);
		Assert.assertEquals(responseOk, locationHeader.getValue());
	}

	@Test
	public void testGenerateLocationHeaderResponse() {
		Header[] headers = new Header[2];
		String value1 = "value1";
		String value2 = "value2";
		String valueLocationHeader = value1 + "," + value2;
		headers[0] = new BasicHeader("Location", valueLocationHeader);
		headers[1] = new BasicHeader("Test1", "");
		Header locationHeader = Main.getLocationHeader(headers);
		String response = Main.generateLocationHeaderResponse(locationHeader);
		String correctResponse = HeaderUtils.X_OCCI_LOCATION_PREFIX + value1 +
				"\n" + HeaderUtils.X_OCCI_LOCATION_PREFIX + value2;
		Assert.assertEquals(correctResponse, response);
	}
	
	@SuppressWarnings("static-access")
	@Test
	public void TestNormalizeToken() throws FileNotFoundException, IOException {
		String token = "Test\nSpace";
		String tokenNormalized = cli.normalizeToken(token);
		Assert.assertEquals(token.replace("\n", ""), tokenNormalized);
				
		File file = new File("src/test/resource/get_content");
		token = IOUtils.toString(new FileInputStream(file));
		Assert.assertTrue(token.length() > 0);
		
		file = new File("src/test/resource/wrong");
		try {
			token = IOUtils.toString(new FileInputStream(file));		
		} catch (Exception e) {
			token = null;
		}
		Assert.assertNull(token);
	}	
	
	@SuppressWarnings("static-access")
	@Test
	public void commandGetMembersUsage() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/usage/members");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "usage --members --url " + Main.DEFAULT_URL
				+ " --auth-token " + ACCESS_TOKEN_ID;

		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}
	
	@SuppressWarnings("static-access")
	@Test
	public void commandGetUsersUsage() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/usage/users");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);
		
		String command = "usage --users --url " + Main.DEFAULT_URL
				+ " --auth-token " + ACCESS_TOKEN_ID;

		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}
	
	@SuppressWarnings("static-access")
	@Test
	public void commandGetMembersAndUsersUsage() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/usage");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);
		
		String command = "usage --users --members --url " + Main.DEFAULT_URL
				+ " --auth-token " + ACCESS_TOKEN_ID;

		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}
	
	private String[] createArgs(String command) throws Exception {
		return command.trim().split(" ");
	}
	
	private class HttpUriRequestMatcher extends ArgumentMatcher<HttpUriRequest> {

		private HttpUriRequest request;

		public HttpUriRequestMatcher(HttpUriRequest request) {
			this.request = request;
		}

		public boolean matches(Object object) {
			HttpUriRequest comparedRequest = (HttpUriRequest) object;
			if (!this.request.getURI().equals(comparedRequest.getURI())) {
				return false;
			}
			if (!checkHeaders(comparedRequest.getAllHeaders())) {
				return false;
			}
			if (!this.request.getMethod().equals(comparedRequest.getMethod())) {
				return false;
			}
			return true;
		}

		public boolean checkHeaders(Header[] comparedHeaders) {
			for (Header comparedHeader : comparedHeaders) {
				boolean headerEquals = false;
				for (Header header : this.request.getAllHeaders()) {
					if (header.getName().equals(OCCIHeaders.X_AUTH_TOKEN)) {
						if (header.getName().equals(comparedHeader.getName())) {
							headerEquals = true;
							break;
						}
					} else 
					if (header.getName().equals(comparedHeader.getName())
							&& header.getValue().equals(comparedHeader.getValue())) {
						headerEquals = true;
						continue;
					}
				}
				if (!headerEquals) {
					return false;
				}
			}
			return true;
		}
	}
}
