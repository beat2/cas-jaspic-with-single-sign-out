/**
 *
 */
package com.googlecode.cas.jaspic.servlet;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

/**
 * @author hisaaki
 * 
 */
public class CasServerAuthContext implements ServerAuthContext {

	private ServerAuthModule module;

	/**
	 * @throws AuthException
	 * 
	 */
	@SuppressWarnings("rawtypes")
	public CasServerAuthContext(CallbackHandler handler, Map properties)
			throws AuthException {
		this.module = new CasServerAuthModule();
		MessagePolicy requestPolicy = new MessagePolicy(null, true);
		MessagePolicy responsePolicy = new MessagePolicy(null, false);
		this.module.initialize(requestPolicy, responsePolicy, handler,
				properties);
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.ServerAuth#validateRequest(javax.security
	 * .auth.message.MessageInfo, javax.security.auth.Subject,
	 * javax.security.auth.Subject)
	 */
	public AuthStatus validateRequest(MessageInfo messageInfo,
			Subject clientSubject, Subject serviceSubject) throws AuthException {
		return this.module.validateRequest(messageInfo, clientSubject,
				serviceSubject);
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.ServerAuth#secureResponse(javax.security.
	 * auth.message.MessageInfo, javax.security.auth.Subject)
	 */
	public AuthStatus secureResponse(MessageInfo messageInfo,
			Subject serviceSubject) throws AuthException {
		return this.module.secureResponse(messageInfo, serviceSubject);
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.ServerAuth#cleanSubject(javax.security.auth
	 * .message.MessageInfo, javax.security.auth.Subject)
	 */
	public void cleanSubject(MessageInfo messageInfo, Subject subject)
			throws AuthException {
		this.module.cleanSubject(messageInfo, subject);
	}

}
