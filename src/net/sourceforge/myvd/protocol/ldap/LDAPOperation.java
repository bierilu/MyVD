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
	    DistinguishedName bindDN = (DistinguishedName) session.getAttribute("MYVD_BINDDN");
	    Password pass = (Password) session.getAttribute("MYVD_BINDPASS");
	    
	    if (bindDN == null) {
	    	bindDN = new DistinguishedName("");
	    	pass = new Password();
	    	
	    	
	    	
	    	userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
	    	session.setAttribute("MYVD_BINDDN",new DistinguishedName(""));
	        session.setAttribute("MYVD_BINDPASS",new Password());
	       
	    }
	    
	    HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
	    
	    String addr = session.getLocalAddress().toString();
	    String host = addr.substring(0,addr.indexOf('/'));
	    String ip = addr.substring(addr.indexOf('/') + 1,addr.indexOf(':'));
	    int port = Integer.parseInt(addr.substring(addr.lastIndexOf(':') + 1));
	    
	    userRequest.put(RequestVariables.MYVD_LOCAL_ADDR, host);
	    userRequest.put(RequestVariables.MYVD_LOCAL_IP, ip);
	    userRequest.put(RequestVariables.MYVD_LOCAL_PORT, port);
	    
	    addr = session.getRemoteAddress().toString();
	    host = addr.substring(0,addr.indexOf('/'));
	    ip = addr.substring(addr.indexOf('/') + 1,addr.indexOf(':'));
	    port = Integer.parseInt(addr.substring(addr.lastIndexOf(':') + 1));
	    
	    userRequest.put(RequestVariables.MYVD_REMOTE_ADDR, host);
	    userRequest.put(RequestVariables.MYVD_REMOTE_IP, ip);
	    userRequest.put(RequestVariables.MYVD_REMOTE_PORT, port);
	    
	    messageReceived(session,request,userRequest,userSession,bindDN,pass);
	}

	
	public void setEnv(Insert[] globalChain,Router router) {
		this.globalChain = globalChain;
		this.router = router;
	}
	
	public abstract void messageReceived( IoSession session, Object request,HashMap userRequest,HashMap userSession,DistinguishedName bindDN,Password pass );

}