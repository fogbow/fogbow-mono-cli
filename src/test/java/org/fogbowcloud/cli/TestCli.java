package org.fogbowcloud.cli;

import java.util.HashMap;
import java.util.Properties;
import java.util.Set;

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
import org.apache.http.message.BasicStatusLine;
import org.fogbowcloud.cli.Main.TokenCommand;
import org.fogbowcloud.manager.core.plugins.IdentityPlugin;
import org.fogbowcloud.manager.core.plugins.util.Credential;
import org.fogbowcloud.manager.occi.core.OCCIHeaders;
import org.fogbowcloud.manager.occi.core.Token;
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
		tokenCommand.type = "OpenStackIdentityPlugin";
		tokenCommand.credentials = new HashMap<String, String>();	
	
		cli.setIdentityPlugin(identityPlugin);
		Assert.assertEquals(accessId, cli.createToken(tokenCommand));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandWithoutUrl() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/compute/");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
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
		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "request --create --n " + intanceCount + " --url " + Main.DEFAULT_URL
				+ " " + "--image " + image + " --flavor " + flavor + " --auth-token "
				+ ACCESS_TOKEN_ID;
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandPostRequestDefaultValues() throws Exception {
		HttpUriRequest request = new HttpPost(Main.DEFAULT_URL + "/" + RequestConstants.TERM);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader("Category", RequestConstants.TERM + "; scheme=\""
				+ RequestConstants.SCHEME + "\"; class=\"" + RequestConstants.KIND_CLASS + "\"");
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.instance-count="
				+ Main.DEFAULT_INTANCE_COUNT);
		request.addHeader("X-OCCI-Attribute", "org.fogbowcloud.request.type=one-time");
		request.addHeader("Category", Main.DEFAULT_FLAVOR + "; scheme=\""
				+ RequestConstants.TEMPLATE_RESOURCE_SCHEME + "\"; class=\""
				+ RequestConstants.MIXIN_CLASS + "\"");
		request.addHeader("Category", Main.DEFAULT_IMAGE + "; scheme=\""
				+ RequestConstants.TEMPLATE_OS_SCHEME + "\"; class=\""
				+ RequestConstants.MIXIN_CLASS + "\"");
		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "request --create --url " + Main.DEFAULT_URL + " --auth-token "
				+ ACCESS_TOKEN_ID;
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandGetSpecificRequest() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/" + RequestConstants.TERM + "/"
				+ REQUEST_ID);
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);

		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
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

		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
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

		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
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
		expectedRequest = new HttpUriRequestMatcher(request);

		String command = "member --get";
		cli.main(createArgs(command));

		Mockito.verify(client).execute(Mockito.argThat(expectedRequest));
	}

	@SuppressWarnings("static-access")
	@Test
	public void commandGetInstance() throws Exception {
		HttpUriRequest request = new HttpGet(Main.DEFAULT_URL + "/compute/");
		request.addHeader(OCCIHeaders.CONTENT_TYPE, OCCIHeaders.OCCI_CONTENT_TYPE);
		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
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
		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
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
		request.addHeader(OCCIHeaders.X_FEDERATION_AUTH_TOKEN, ACCESS_TOKEN_ID);
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
			} catch (Exception e) {
			}
			for (Credential credential : identityPlugin.getCredentials()) {
				Assert.assertTrue(response.contains(credential.getName()));
				if (credential.getValueDefault() != null) {
					Assert.assertTrue(response.contains(credential.getValueDefault()));
				}
			}
		}

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
