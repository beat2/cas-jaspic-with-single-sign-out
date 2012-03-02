package com.googlecode.cas.jaspic.session;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.XmlUtils;

/**
 * Performs CAS single sign-out operations in an API-agnostic fashion.
 * 
 * @author Marvin S. Addison
 * @version $Revision: 24094 $ $Date: 2011-06-20 21:39:49 -0400 (Mon, 20 Jun
 *          2011) $
 * @since 3.1.12
 * 
 */
public final class SessionHandler {

	/** Logger instance */
	private final static Logger log = Logger.getLogger(SessionHandler.class
			.getName());

	/** Mapping of token IDs and session IDs to HTTP sessions */
	private ISessionRegistry sessionMappingStorage = new SessionRegistry();

	/**
	 * The name of the artifact parameter. This is used to capture the session
	 * identifier.
	 */
	private String artifactParameterName = "ticket";

	/** Parameter name that stores logout request */
	private String logoutParameterName = "logoutRequest";

	public void setSessionMappingStorage(final ISessionRegistry storage) {
		this.sessionMappingStorage = storage;
	}

	public ISessionRegistry getSessionMappingStorage() {
		return this.sessionMappingStorage;
	}

	/**
	 * @param name
	 *            Name of the authentication token parameter.
	 */
	public void setArtifactParameterName(final String name) {
		this.artifactParameterName = name;
	}

	/**
	 * @param name
	 *            Name of parameter containing CAS logout request message.
	 */
	public void setLogoutParameterName(final String name) {
		this.logoutParameterName = name;
	}

	/**
	 * Determines whether the given request contains an authentication token.
	 * 
	 * @param request
	 *            HTTP reqest.
	 * 
	 * @return True if request contains authentication token, false otherwise.
	 */
	public boolean isTokenRequest(final HttpServletRequest request) {
		return CommonUtils.isNotBlank(CommonUtils.safeGetParameter(request,
				this.artifactParameterName));
	}

	/**
	 * Determines whether the given request is a CAS logout request.
	 * 
	 * @param request
	 *            HTTP request.
	 * 
	 * @return True if request is logout request, false otherwise.
	 */
	public boolean isLogoutRequest(final HttpServletRequest request) {
		return "POST".equals(request.getMethod())
				&& !isMultipartRequest(request)
				&& CommonUtils.isNotBlank(CommonUtils.safeGetParameter(request,
						this.logoutParameterName));
	}

	/**
	 * Associates a token request with the current HTTP session by recording the
	 * mapping in the the configured {@link ISessionRegistry} container.
	 * 
	 * @param request
	 *            HTTP request containing an authentication token.
	 */
	public void recordSession(final HttpServletRequest request) {
		final HttpSession session = request.getSession(true);

		final String token = CommonUtils.safeGetParameter(request,
				this.artifactParameterName);

		log.fine("Recording session for token " + token);

		try {
			this.sessionMappingStorage.removeSessionByMappingId(token);
		} catch (final Exception e) {
			// ignore if the session is already marked as invalid. Nothing we
			// can do!
		}
		sessionMappingStorage.addSessionById(token, session);
	}

	/**
	 * Destroys the current HTTP session for the given CAS logout request.
	 * 
	 * @param request
	 *            HTTP request containing a CAS logout message.
	 */
	public void destroySession(final HttpServletRequest request) {
		final String logoutMessage = CommonUtils.safeGetParameter(request,
				this.logoutParameterName);

		log.fine("Logout request:\n" + logoutMessage);

		final String token = XmlUtils.getTextForElement(logoutMessage,
				"SessionIndex");
		if (CommonUtils.isNotBlank(token)) {
			final HttpSession session = this.sessionMappingStorage
					.removeSessionByMappingId(token);

			if (session != null) {
				String sessionID = session.getId();

				log.fine("Invalidating session [" + sessionID + "] for token ["
						+ token + "]");

				try {
					session.invalidate();
				} catch (final IllegalStateException e) {
					log.log(Level.FINE, "Error invalidating session.", e);
				}
			}
		}
	}

	private boolean isMultipartRequest(final HttpServletRequest request) {
		return request.getContentType() != null
				&& request.getContentType().toLowerCase()
						.startsWith("multipart");
	}
}
