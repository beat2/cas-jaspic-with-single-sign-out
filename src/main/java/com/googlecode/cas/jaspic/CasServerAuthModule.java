package com.googlecode.cas.jaspic;

import static org.jasig.cas.client.util.AbstractCasFilter.CONST_CAS_ASSERTION;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.jaas.AssertionPrincipal;
import org.jasig.cas.client.jaas.ServiceAndTicketCallbackHandler;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;

public class CasServerAuthModule implements ServerAuthModule {

	protected static final Class[] supportedMessageTypes = new Class[] {
			HttpServletRequest.class, HttpServletResponse.class };

	private MessagePolicy requestPolicy;
	private MessagePolicy responsePolicy;
	private CallbackHandler handler;
	private Map options;
	private String serverName = null;
	private String casUrl = null;
	private String casLoginUrl = null;
	private String realmName = null;
	private String defaultGroup[] = null;
	private String service = null;
	private boolean sfc = false;
	private String serviceParameterName = "service";
	private static final String SERVER_NAME = "serverName";
	private static final String CAS_URL = "cas-url";
	private static final String CAS_LOGIN_URL = "cas-login-url";
	private static final String SUCCESS_FOR_CONTINUE = "success-for-continue";
	private static final String REQUEST_TICKET = "ticket";
	private static final String REALM_PROPERTY_NAME = "realm-name";
	private static final String GROUP_PROPERTY_NAME = "group-name";
	private static final String BASIC = "Basic";
	static final String LOCATION_HEADER = "Location";
	static final String SESSION_ASSERTION = "session-assertion";
	
	public CasServerAuthModule(){}
	
	public CasServerAuthModule(String str){}

	public void initialize(MessagePolicy reqPolicy, MessagePolicy resPolicy,
			CallbackHandler cBH, Map opts) throws AuthException {
		requestPolicy = reqPolicy;
		responsePolicy = resPolicy;
		handler = cBH;
		options = opts;
		if (options != null) {
			serverName = (String) options.get(SERVER_NAME);
			casUrl = (String) options.get(CAS_URL);
			casLoginUrl = (String) options.get(CAS_LOGIN_URL);
			sfc = Boolean.parseBoolean((String)options.get(SUCCESS_FOR_CONTINUE));
			realmName = (String) options.get(REALM_PROPERTY_NAME);
			if (options.containsKey(GROUP_PROPERTY_NAME)) {
				defaultGroup = new String[] { (String) options
						.get(GROUP_PROPERTY_NAME) };
			}
		}
	}

	public Class[] getSupportedMessageTypes() {
		return supportedMessageTypes;
	}

	public AuthStatus validateRequest(MessageInfo msgInfo, Subject client,
			Subject server) throws AuthException {
		try {
			HttpServletRequest request = (HttpServletRequest) msgInfo
					.getRequestMessage();
			HttpServletResponse response = (HttpServletResponse) msgInfo
					.getResponseMessage();
			HttpSession session = request.getSession();
			Assertion assertion = (Assertion) session
					.getAttribute(CONST_CAS_ASSERTION);
			if (assertion == null) {
				service = CommonUtils.constructServiceUrl(request, response,
						null, serverName, REQUEST_TICKET, false);
				final String ticket = CommonUtils.safeGetParameter(request,
						REQUEST_TICKET);
				LoginContext lc = new LoginContext("cas",
						new ServiceAndTicketCallbackHandler(service, ticket));
				lc.login();
				Subject subject = lc.getSubject();
				for (Principal p : subject.getPrincipals()) {
					if (p instanceof AssertionPrincipal) {
						session.setAttribute(CONST_CAS_ASSERTION,
								((AssertionPrincipal) p).getAssertion());
						break;
					}
				}
			}
			return AuthStatus.SUCCESS;
		} catch (Exception e) {
			if (e.getCause() instanceof TicketValidationException) {
				return AuthStatus.SEND_FAILURE;
			}
			return sendAuthenticateChallenge(msgInfo);
		}
	}

	private AuthStatus sendAuthenticateChallenge(MessageInfo msgInfo) {
		HttpServletResponse response = (HttpServletResponse) msgInfo
				.getResponseMessage();
		try {
			response.sendRedirect(CommonUtils.constructRedirectUrl(casLoginUrl,
					serviceParameterName, service, false, false));
		} catch (IOException e) {
			e.printStackTrace();
		}
		if(sfc){
			return AuthStatus.SUCCESS;
		}else{
			return AuthStatus.SEND_CONTINUE;
		}
		
	}

	public AuthStatus secureResponse(MessageInfo msgInfo, Subject service)
			throws AuthException {
		return AuthStatus.SEND_SUCCESS;
	}

	public void cleanSubject(MessageInfo msgInfo, Subject subject)
			throws AuthException {
		if (subject != null) {
			subject.getPrincipals().clear();
		}
	}

	private static final String AUTH_TYPE_INFO_KEY = "javax.servlet.http.authType";

}
