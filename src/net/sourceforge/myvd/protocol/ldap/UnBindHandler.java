package net.sourceforge.myvd.protocol.ldap;

/*
 *   Copyright 2004 The Apache Software Foundation
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */



import java.util.ArrayList;
import java.util.HashMap;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.SessionVariables;

import org.apache.mina.protocol.ProtocolSession;
import org.apache.mina.protocol.handler.MessageHandler;



/**
 * A no reply protocol handler implementation for LDAP {@link
 * org.apache.ldap.common.message.UnbindRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 161724 $
 */
public class UnBindHandler implements MessageHandler,LdapInfo
{
    public void messageReceived( ProtocolSession session, Object request )
    {
//    	reset the session username and pass
    	HashMap userSession = (HashMap) session.getAttribute("MYVD_SESSION");
    	userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
    	session.setAttribute("MYVD_BINDDN",new DistinguishedName(""));
        session.setAttribute("MYVD_BINDPASS",new Password());
    }

	public void setEnv(Insert[] globalChain, Router router) {
		// TODO Auto-generated method stub
		
	}
}
