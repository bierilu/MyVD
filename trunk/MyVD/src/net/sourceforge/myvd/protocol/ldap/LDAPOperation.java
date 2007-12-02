/*
 * Copyright 2006 Marc Boorshtein 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package net.sourceforge.myvd.protocol.ldap;

import java.util.ArrayList;
import java.util.HashMap;

import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.RequestVariables;
import net.sourceforge.myvd.types.SessionVariables;



import org.apache.mina.common.IoSession;
import org.apache.mina.handler.demux.MessageHandler;

public abstract class LDAPOperation implements MessageHandler {

	Insert[] globalChain;
    Router router;
	
	public LDAPOperation() {
		super();
	}

	public void messageReceived(IoSession session, Object request) {
		HashMap userSession = null;
		
		
		
		userSession = (HashMap) session.getAttribute("MYVD_SESSION");
		if (userSession == null) {
			userSession = new HashMap();
			session.setAttribute("MYVD_SESSION", userSession);
		}
	    DistinguishedName bindDN = (DistinguishedName) userSession.get("MYVD_BINDDN");
	    Password pass = (Password) userSession.get("MYVD_BINDPASS");
	    
	    if (bindDN == null) {
	    	bindDN = new DistinguishedName("");
	    	pass = new Password();
	    	
	    	
	    	
	    	userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
	    	userSession.put("MYVD_BINDDN",new DistinguishedName(""));
	    	userSession.put("MYVD_BINDPASS",new Password());
	       
	    }
	    
	    HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
	    
	    String addr = session.getLocalAddress().toString();
	    String host = addr.substring(0,addr.indexOf('/'));
	    String ip = addr.substring(addr.indexOf('/') + 1,addr.indexOf(':'));
	    int port = Integer.parseInt(addr.substring(addr.lastIndexOf(':') + 1));
	    
	    setLocalConInfo(userRequest, host, ip, port);
	    
	    addr = session.getRemoteAddress().toString();
	    host = addr.substring(0,addr.indexOf('/'));
	    ip = addr.substring(addr.indexOf('/') + 1,addr.indexOf(':'));
	    port = Integer.parseInt(addr.substring(addr.lastIndexOf(':') + 1));
	    
	    setRemoteConInfo(userRequest, host, ip, port);
	    
	    messageReceived(session,request,userRequest,userSession,bindDN,pass);
	}

	private void setRemoteConInfo(HashMap<Object, Object> userRequest, String host, String ip, int port) {
		userRequest.put(RequestVariables.MYVD_REMOTE_ADDR, host);
	    userRequest.put(RequestVariables.MYVD_REMOTE_IP, ip);
	    userRequest.put(RequestVariables.MYVD_REMOTE_PORT, port);
	}

	private void setLocalConInfo(HashMap<Object, Object> userRequest, String host, String ip, int port) {
		userRequest.put(RequestVariables.MYVD_LOCAL_ADDR, host);
	    userRequest.put(RequestVariables.MYVD_LOCAL_IP, ip);
	    userRequest.put(RequestVariables.MYVD_LOCAL_PORT, port);
	}

	
	public void setEnv(Insert[] globalChain,Router router) {
		this.globalChain = globalChain;
		this.router = router;
	}
	
	public abstract void messageReceived( IoSession session, Object request,HashMap userRequest,HashMap userSession,DistinguishedName bindDN,Password pass );

}