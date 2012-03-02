package com.googlecode.cas.jaspic.session;

import java.util.Collection;
import javax.servlet.http.HttpSession;

/**
 * Stores the mapping between sessions and keys (ticket-number from cas) to be
 * retrieved later.<br>
 * Modified to get the whole Collection of HttpSessions, so we can check and see
 * which of them are obsolete and can be removed. This is needed, because we do
 * not want to have a HttpSessionListener in each WebApplication. The
 * SessionListener would remove the sessions on invalidation, which we just
 * ignore now and clean up by hand.
 * 
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 3.1
 * 
 */
public interface ISessionRegistry {

	/**
	 * Remove the HttpSession based on the mappingId.
	 * 
	 * @param mappingId
	 *            the id the session is keyed under.
	 * @return the HttpSession if it exists.
	 */
	HttpSession removeSessionByMappingId(String mappingId);

	/**
	 * Add a session by its mapping Id.
	 * 
	 * @param mappingId
	 *            the id to map the session to.
	 * @param session
	 *            the HttpSession.
	 */
	void addSessionById(String mappingId, HttpSession session);

	/**
	 * Returns complete Collection of HttpSession objects, which may be
	 * invalidated already.
	 * 
	 * @return all HttpSessions
	 */
	Collection<HttpSession> getAllSessions();

}
