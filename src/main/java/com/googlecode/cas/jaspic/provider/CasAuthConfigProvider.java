/**
 *
 */
package com.googlecode.cas.jaspic.provider;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;

import com.googlecode.cas.jaspic.servlet.CasServerAuthConfig;

/**
 * @author hisaaki
 * 
 */
public class CasAuthConfigProvider implements AuthConfigProvider {

	private ServerAuthConfig serverAuthConfig = null;

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.config.AuthConfigProvider#getClientAuthConfig
	 * (java.lang.String, java.lang.String,
	 * javax.security.auth.callback.CallbackHandler)
	 */
	public ClientAuthConfig getClientAuthConfig(String layer,
			String appContext, CallbackHandler handler) throws AuthException {
		ClientAuthConfig config = null;
		return config;
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * javax.security.auth.message.config.AuthConfigProvider#getServerAuthConfig
	 * (java.lang.String, java.lang.String,
	 * javax.security.auth.callback.CallbackHandler)
	 */
	public ServerAuthConfig getServerAuthConfig(String layer,
			String appContext, CallbackHandler handler) throws AuthException {
		if ("HttpServlet".equals(layer)) {
			this.serverAuthConfig = new CasServerAuthConfig(appContext, handler);
		}
		return this.serverAuthConfig;
	}

	/*
	 * (non-Javadoc)
	 * @see javax.security.auth.message.config.AuthConfigProvider#refresh()
	 */
	public void refresh() {
		this.serverAuthConfig = null;
	}

}
