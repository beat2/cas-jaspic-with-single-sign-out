/**
 *
 */
package com.googlecode.cas.jaspic.servlet;

import static com.googlecode.cas.jaspic.util.Constants.AUTH_TYPE_HTTP_SERVLET;
import static com.googlecode.cas.jaspic.util.Constants.MESSAGE_LAYER_HTTP_SERVLET;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;

/**
 * @author hisaaki
 * 
 */
public class CasServerAuthConfig implements ServerAuthConfig {

	private String appContext = null;

	private CallbackHandler handler = null;

	private ServerAuthContext context;

	public CasServerAuthConfig(String appContext, CallbackHandler handler) {
		this.appContext = appContext;
		this.handler = handler;
	}

	/*
	 * (non-Javadoc)
	 * @see javax.security.auth.message.config.AuthConfig#getAppContext()
	 */
	public String getAppContext() {
		return this.appContext;
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.config.AuthConfig#getAuthContextID(javax.
	 * security.auth.message.MessageInfo)
	 */
	public String getAuthContextID(MessageInfo messageInfo) {
		return (String) messageInfo.getMap().get(AUTH_TYPE_HTTP_SERVLET);
	}

	/*
	 * (non-Javadoc)
	 * @see javax.security.auth.message.config.AuthConfig#getMessageLayer()
	 */
	public String getMessageLayer() {
		return MESSAGE_LAYER_HTTP_SERVLET;
	}

	/*
	 * (non-Javadoc)
	 * @see javax.security.auth.message.config.AuthConfig#isProtected()
	 */
	public boolean isProtected() {
		return false;
	}

	/*
	 * (non-Javadoc)
	 * @see javax.security.auth.message.config.AuthConfig#refresh()
	 */
	public void refresh() {
		this.context = null;
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.config.ServerAuthConfig#getAuthContext(java
	 * .lang.String, javax.security.auth.Subject, java.util.Map)
	 */
	@SuppressWarnings("rawtypes")
	public ServerAuthContext getAuthContext(String authContextId,
			Subject subject, Map properties) throws AuthException {
		if (this.context == null) {
			this.context = new CasServerAuthContext(handler, properties);
		}
		return this.context;
	}

}
