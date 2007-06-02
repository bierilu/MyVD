package net.sourceforge.myvd.server;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;

import com.novell.ldap.LDAPException;
import com.novell.ldap.util.DN;

public class ServerCore {
	static Logger logger = Logger.getLogger(ServerCore.class);
	
	Properties props;
	private Insert[] globalChain;
	private Router router;
	
	public ServerCore(Properties props) {
		this.props = props;
	}

	public Insert[] getGlobalChain() {
		return globalChain;
	}

	public Properties getProps() {
		return props;
	}

	public Router getRouter() {
		return router;
	}

	private Insert configureInterceptor(String name,String prefix,NameSpace ns) throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		logger.debug("Insert : " + name + "; " + prefix);
		
		String className = props.getProperty(prefix + "className");
		
		logger.debug("Insert Class Name : " + className);
		
		String cfgPrefix = prefix + "config.";
		Insert interceptor;
		
		interceptor = (Insert) Class.forName(className).newInstance();
		String propName;
		Properties localProps = new Properties();
		Iterator it = props.keySet().iterator();
		while (it.hasNext()) {
			propName = (String) it.next();
			if (propName.startsWith(cfgPrefix)) {
				String localPropName = propName.substring(cfgPrefix.length());
				String localVal = props.getProperty(propName);
				localVal = envVars(localVal);
				logger.debug("Config : " + localPropName + "=" + localVal);
				localProps.setProperty(localPropName,localVal);
			}
		}
		
		interceptor.configure(name,localProps,ns);
		
		return interceptor;
		
		
	}
	
	private String envVars(String localVal) {
		int start = localVal.indexOf('%');
		
		int last = 0;
		if (start == -1) {
			return localVal;
		}
		
		
		
		StringBuffer buf = new StringBuffer();
		
		while (start != -1) {
			int end = localVal.indexOf('%',start + 1);
			if (end == -1) {
				return localVal;
			}
			buf.append(localVal.substring(last,start));
			buf.append(System.getenv().get(localVal.substring(start + 1,end)));
			last = end + 1;
			start = localVal.indexOf('%',last);
		}
		
		buf.append(localVal.substring(last));
		
		return buf.toString();
	}

	private void configureChain(String prefix,ArrayList<String> links,Insert[] chain,NameSpace ns) throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		Iterator<String> it = links.iterator();
		int i=0;
		
		while (it.hasNext()) {
			String name = it.next();
			chain[i] = this.configureInterceptor(name,prefix +  name + ".",ns);
			i++;
		}
	}
	
	private void buildGlobalChain() throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		String links = props.getProperty("server.globalChain");
		ArrayList<String> linkList = new ArrayList<String>();
		
		StringTokenizer toker = new StringTokenizer(links,",");
		
		while (toker.hasMoreTokens()) {
			linkList.add(toker.nextToken());
		}
		
		Insert[] chain = new Insert[linkList.size()];
		
		this.configureChain("server.globalChain.",linkList,chain,null);
		
		this.globalChain = chain;
		
	}
	
	private void buildNamespaces() throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		String nss = props.getProperty("server.nameSpaces");
		StringTokenizer toker = new StringTokenizer(nss,",");
		Router router = new Router(this.globalChain);
		while (toker.hasMoreTokens()) {
			
			
			String nsName = toker.nextToken();
			
			logger.debug("Loading namespace : " + nsName);
			
			String prefix = "server." + nsName + ".";
			int weight = Integer.parseInt(props.getProperty(prefix + "weight","0"));
			String nsBase = props.getProperty(prefix + "nameSpace");
			
			String nsChain = props.getProperty(prefix + "chain");
			StringTokenizer chainToker = new StringTokenizer(nsChain,",");
			
			ArrayList<String> chainList = new ArrayList<String>();
			
			while (chainToker.hasMoreTokens()) {
				chainList.add(chainToker.nextToken());
			}
			
			Insert[] chain = new Insert[chainList.size()];
			
			NameSpace ns = new NameSpace(nsName,new DistinguishedName(nsBase),weight,chain);
			
			this.configureChain(prefix,chainList,chain,ns);
			
			router.addBackend(nsName,new DN(nsBase),ns);
		}
		
		this.router = router;
	}
	
	public void startService() throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		logger.debug("Loading global chain...");
		this.buildGlobalChain();
		logger.debug("Global chain loaded");
		logger.debug("Loading local chain...");
		this.buildNamespaces();
		logger.debug("Local chain loaded");
	}
}
