package com.hxperience.thingworx.authenticators;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;

import com.thingworx.common.SharedConstants;
import com.thingworx.logging.LogUtilities;
import com.thingworx.security.authentication.AuthenticationUtilities;
import com.thingworx.security.authentication.AuthenticatorException;
import com.thingworx.security.authentication.CustomAuthenticator;
import com.thingworx.security.users.User;
import com.thingworx.system.managers.UserManager;
import com.thingworx.types.InfoTable;
import com.thingworx.types.collections.ValueCollection;
import com.thingworx.types.primitives.StringPrimitive;

public class CustomFormAuthenticator extends CustomAuthenticator {

	public final static String FORM_USERNAME_FIELD = "twx-username";
	public final static String FORM_PASSWORD_FIELD = "twx-password";
	public final static String FORM_ORG_FIELD = "OrganizationName";
	
	private static final long serialVersionUID = 1L;
	protected static Logger APP_LOGGER = LogUtilities.getInstance().getApplicationLogger(CustomFormAuthenticator.class);
	protected static Logger SECU_LOGGER = LogUtilities.getInstance().getSecurityLogger(CustomFormAuthenticator.class);

	public CustomFormAuthenticator() {
		super();
		this.setName(this.getClass().getSimpleName());
	}

	@Override
	public boolean matchesAuthRequest(HttpServletRequest req) {
		return req.getParameter(FORM_USERNAME_FIELD) != null
				&& req.getParameter(FORM_PASSWORD_FIELD) != null
				&& req.getParameter(FORM_ORG_FIELD) != null;
	}

	@Override
	/**
	 * Throw an Exception if the login is not valid
	 */
	public void authenticate(HttpServletRequest req, HttpServletResponse res) throws AuthenticatorException {

		// intercept requests with the ThingworxFormAuthenticator parameters
		String userName = req.getParameter(FORM_USERNAME_FIELD);
		String password = req.getParameter(FORM_PASSWORD_FIELD);
		String org = req.getParameter(FORM_ORG_FIELD);
		SECU_LOGGER.warn(req.getContextPath());
		SECU_LOGGER.info("Trying to connect : " +userName + " via the Custom Login Form for "+org);
		try
		{
			User user = UserManager.getInstance().getEntityDirect(userName);
			if(user == null)
				throw new AuthenticatorException(userName + " doesn't exist as a user in TW");
            InfoTable it = user.GetOrganizations();
            ValueCollection vc = new ValueCollection();
            vc.put("name", new StringPrimitive(org));
            boolean isInOrg = it.getRows().find(vc) != null;
            SECU_LOGGER.debug(userName+" E "+org+"="+isInOrg);
            
            if(isInOrg){
	            // Validates that a Thingworx user exists
	            AuthenticationUtilities.validateCredentials(userName, password);
	            
	            // Set the credentials
	            this.setCredentials(userName, password);
	            
	            AuthenticationUtilities.getSecurityMonitorThing().fireSuccessfulLoginEvent(userName,SharedConstants.EMPTY_STRING);

            } else {
            	throw new AuthenticatorException("tried to authenticate for " + org + " but does not belong to it");
            }
		}
		catch(AuthenticatorException eValidate)
		{
			try {
				AuthenticationUtilities.getSecurityMonitorThing().fireFailedLoginEvent(userName,eValidate.getMessage());
			} catch (Exception e) {}
			req.setAttribute("l_err", true);
			throw eValidate;
			
		} catch (Exception e) {
			req.setAttribute("s_err", true);
			setRequiresChallenge(true);
			APP_LOGGER.error(e.toString());
		}
	}

	@Override
	public void issueAuthenticationChallenge(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticatorException {
		SECU_LOGGER.error("Sh*t happens ...");
		boolean loginError = req.getAttribute("l_err") != null;
		boolean serverError = req.getAttribute("s_err") != null;
		String p ="";
		if(loginError) p="?l_err=true";
		else if(serverError) p="?s_err=true";
		try {
			//Faute de mieux, redirection avec paramètre dans l'url
			res.sendRedirect(req.getParameter("redirect")+p);
		} catch (Exception e) {
			APP_LOGGER.error(e.toString());
		}
		
	}

}
