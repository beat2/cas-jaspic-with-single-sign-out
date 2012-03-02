package com.googlecode.cas.jaspic.session;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpSession;

/**
 * HashMap backed implementation of SessionMappingStorage.
 * 
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 3.1
 * 
 */
public final class SessionRegistry implements ISessionRegistry {

	/**
	 * Maps the ID from the CAS server to the Session.
	 */
	private final Map<String, HttpSession> MANAGED_SESSIONS = new HashMap<String, HttpSession>();

	public synchronized void addSessionById(String mappingId,
			HttpSession session) {
		MANAGED_SESSIONS.put(mappingId, session);
	}

	public synchronized HttpSession removeSessionByMappingId(String mappingId) {
		return MANAGED_SESSIONS.remove(mappingId);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.googlecode.cas.jaspic.util.SessionMappingStorage#getAllSessions()
	 */
	public Collection<HttpSession> getAllSessions() {
		return MANAGED_SESSIONS.values();
	}
}
