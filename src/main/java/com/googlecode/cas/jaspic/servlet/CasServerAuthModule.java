package com.googlecode.cas.jaspic.servlet;

import static com.googlecode.cas.jaspic.util.Constants.AUTH_TYPE_HTTP_SERVLET;
import static com.googlecode.cas.jaspic.util.Constants.PROPERTY_CAS_SERVER_LOGIN_URL;
import static com.googlecode.cas.jaspic.util.Constants.PROPERTY_CAS_SERVER_URL_PREFIX;
import static com.googlecode.cas.jaspic.util.Constants.PROPERTY_DEFAULT_GROUPS;
import static com.googlecode.cas.jaspic.util.Constants.PROPERTY_GROUP_ATTRIBUTE_NAMES;
import static com.googlecode.cas.jaspic.util.Constants.PROPERTY_JAAS_CONTEXT;
import static com.googlecode.cas.jaspic.util.Constants.PROPERTY_SERVER_NAME;
import static com.googlecode.cas.jaspic.util.Constants.PROPERTY_SERVICE;
import static javax.security.auth.message.AuthStatus.SEND_CONTINUE;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SEND_SUCCESS;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.jasig.cas.client.util.AbstractCasFilter.CONST_CAS_ASSERTION;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.jaas.AssertionPrincipal;
import org.jasig.cas.client.jaas.ServiceAndTicketCallbackHandler;
import org.jasig.cas.client.util.AssertionHolder;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;

/**
 * @author hisaaki
 * 
 */
@SuppressWarnings({ "rawtypes", "unused" })
public class CasServerAuthModule implements ServerAuthModule {

	private static final Class[] supportedMessageTypes = new Class[]{
			HttpServletRequest.class, HttpServletResponse.class };

	private static Logger logger = Logger.getLogger(CasServerAuthModule.class
			.getName());

	private MessagePolicy requestPolicy;
	private MessagePolicy responsePolicy;
	private CallbackHandler handler;
	private Map properties;

	private String service = null;
	private String serverName = null;
	private String artifactParameterName = "ticket";
	private String serviceParameterName = "service";
	private boolean encodeServiceUrl = false;

	private boolean redirectAfterValidation = true;
	private String casServerUrlPrefix = null;
	private String casServerLoginUrl = null;
	private boolean renew = false;
	private boolean gateway = false;

	private String jaasContext = "cas";
	private String defaultGroups[] = null;
	private String groupAttributeNames[] = null;

	private LoginContext lc;

	public CasServerAuthModule() {
	}

	public CasServerAuthModule(String str) {
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.module.ServerAuthModule#getSupportedMessageTypes
	 * ()
	 */
	public Class[] getSupportedMessageTypes() {
		return supportedMessageTypes;
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.ServerAuth#secureResponse(javax.security.
	 * auth.message.MessageInfo, javax.security.auth.Subject)
	 */
	public AuthStatus secureResponse(MessageInfo msgInfo, Subject service)
			throws AuthException {
		AssertionHolder.clear();
		return SEND_SUCCESS;
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.ServerAuth#cleanSubject(javax.security.auth
	 * .message.MessageInfo, javax.security.auth.Subject)
	 */
	public void cleanSubject(MessageInfo msgInfo, Subject subject)
			throws AuthException {
		if (subject != null) {
			subject.getPrincipals().clear();
		}
		if (this.lc != null) {
			try {
				this.lc.logout();
			} catch (LoginException e) {
				logger.throwing(CasServerAuthModule.class.getName(),
						"cleanSubject", e);
				AuthException ae = new AuthException();
				ae.initCause(e);
				throw ae;
			}
		}
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.module.ServerAuthModule#initialize(javax.
	 * security.auth.message.MessagePolicy,
	 * javax.security.auth.message.MessagePolicy,
	 * javax.security.auth.callback.CallbackHandler, java.util.Map)
	 */
	public void initialize(MessagePolicy requestPolicy,
			MessagePolicy responsePolicy, CallbackHandler handler,
			Map properties) throws AuthException {
		this.requestPolicy = requestPolicy;
		this.responsePolicy = responsePolicy;
		this.handler = handler;
		this.properties = properties;
		if (properties != null) {
			this.service = (String) properties.get(PROPERTY_SERVICE);
			this.serverName = (String) properties.get(PROPERTY_SERVER_NAME);
			this.casServerUrlPrefix = (String) properties
					.get(PROPERTY_CAS_SERVER_URL_PREFIX);
			this.casServerLoginUrl = (String) properties
					.get(PROPERTY_CAS_SERVER_LOGIN_URL);
			if (properties.containsKey(PROPERTY_JAAS_CONTEXT)) {
				this.jaasContext = (String) properties
						.get(PROPERTY_JAAS_CONTEXT);
			}
			if (properties.containsKey(PROPERTY_DEFAULT_GROUPS)) {
				String value = (String) properties.get(PROPERTY_DEFAULT_GROUPS);
				if (value != null) {
					this.defaultGroups = value.split(",\\s*");
				}
			}
			if (properties.containsKey(PROPERTY_GROUP_ATTRIBUTE_NAMES)) {
				String value = (String) properties
						.get(PROPERTY_GROUP_ATTRIBUTE_NAMES);
				if (value != null) {
					this.groupAttributeNames = value.split(",\\s*");
				}
			}
		}
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.ServerAuth#validateRequest(javax.security
	 * .auth.message.MessageInfo, javax.security.auth.Subject,
	 * javax.security.auth.Subject)
	 */
	public AuthStatus validateRequest(MessageInfo msgInfo,
			Subject clientSubject, Subject serverSubject) throws AuthException {
		HttpServletRequest request = (HttpServletRequest) msgInfo
				.getRequestMessage();
		HttpServletResponse response = (HttpServletResponse) msgInfo
				.getResponseMessage();
		HttpSession session = request.getSession();
		try {
			Assertion assertion = (Assertion) session
					.getAttribute(CONST_CAS_ASSERTION);
			if (assertion != null) {
				if (this.redirectAfterValidation) {
					String ticket = getTicket(request);
					if (ticket != null) {
						logger.fine("Redirecting after check assertion.");
						response.sendRedirect(constructServiceUrl(request,
								response));
						return SEND_CONTINUE;
					}
				}
				setAuthenticationResult(assertion, clientSubject, msgInfo);
				return SUCCESS;
			}
			if (!this.requestPolicy.isMandatory()) {
				return SUCCESS;
			}
			String ticket = getTicket(request);
			if (ticket == null || ticket.length() == 0) {
				response.sendRedirect(constructRedirectUrl(request, response));
				return SEND_CONTINUE;
			}
			String serviceUrl = constructServiceUrl(request, response);
			this.lc = new LoginContext(this.jaasContext,
					new ServiceAndTicketCallbackHandler(serviceUrl, ticket));
			lc.login();
			Subject subject = lc.getSubject();
			for (Principal p : subject.getPrincipals()) {
				if (p instanceof AssertionPrincipal) {
					assertion = ((AssertionPrincipal) p).getAssertion();
					session.setAttribute(CONST_CAS_ASSERTION, assertion);
					if (this.redirectAfterValidation) {
						logger.fine("Redirecting after successful ticket validation.");
						response.sendRedirect(constructServiceUrl(request,
								response));
						return SEND_CONTINUE;
					}
					setAuthenticationResult(assertion, clientSubject, msgInfo);
					return SUCCESS;
				}
			}
			return SEND_FAILURE;
		} catch (Exception e) {
			if (e.getCause() instanceof TicketValidationException) {
				logger.warning(e.getMessage());
				try {
					logger.fine("Redirecting because of an invalid ticket.");
					response.sendRedirect(constructRedirectUrl(request,
							response));
					return SEND_CONTINUE;
				} catch (IOException ioe) {
					logger.throwing(CasServerAuthModule.class.getName(),
							"validateRequest", ioe);
				}
			}
			logger.throwing(CasServerAuthModule.class.getName(),
					"validateRequest", e);
			AuthException ae = new AuthException();
			ae.initCause(e);
			throw ae;
		}
	}

	private String getTicket(HttpServletRequest request) {
		return CommonUtils
				.safeGetParameter(request, this.artifactParameterName);
	}

	@SuppressWarnings("unchecked")
	private void setAuthenticationResult(Assertion assertion, Subject subject,
			MessageInfo m) throws IOException, UnsupportedCallbackException {
		if (assertion != null) {
			AssertionHolder.setAssertion(assertion);
			Principal principal = assertion.getPrincipal();
			this.handler.handle(new Callback[]{ new CallerPrincipalCallback(
					subject, principal) });
			m.getMap().put(AUTH_TYPE_HTTP_SERVLET,
					CasServerAuthModule.class.getName());
			List groups = new ArrayList();
			if (this.defaultGroups != null) {
				groups.addAll(Arrays.asList(this.defaultGroups));
			}
			if (this.groupAttributeNames != null) {
				for (String key : groupAttributeNames) {
					String value = (String) assertion.getAttributes().get(key);
					if (value != null) {
						groups.addAll(Arrays.asList(value.split(",\\s*")));
					}
				}
			}
			if (groups.size() > 0) {
				String[] group = new String[groups.size()];
				this.handler.handle(new Callback[]{ new GroupPrincipalCallback(
						subject, (String[]) groups.toArray(group)) });
			}
		}
	}

	private String constructServiceUrl(HttpServletRequest request,
			HttpServletResponse response) {
		return CommonUtils.constructServiceUrl(request, response, this.service,
				this.serverName, this.artifactParameterName,
				this.encodeServiceUrl);
	}

	private String constructRedirectUrl(HttpServletRequest request,
			HttpServletResponse response) {
		return CommonUtils.constructRedirectUrl(this.casServerLoginUrl,
				this.serviceParameterName,
				constructServiceUrl(request, response), this.renew,
				this.gateway);
	}

}
