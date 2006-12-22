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
package net.sourceforge.myvd.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.protocol.ldap.LdapProtocolProvider;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;

import org.apache.ldap.common.exception.LdapNamingException;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.mina.common.TransportType;
import org.apache.mina.io.filter.SSLFilter;
import org.apache.mina.registry.Service;
import org.apache.mina.registry.ServiceRegistry;
import org.apache.mina.registry.SimpleServiceRegistry;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.util.DN;


public class Server {
	
	static Logger logger;
	
	String configFile;
	Properties props;
	private Insert[] globalChain;
	private Router router;
	ServiceRegistry minaRegistry;
	ServiceRegistry sslMinaRegistry;
	
	public Insert[] getGlobalChain() {
		return globalChain;
	}

	public Router getRouter() {
		return router;
	}

	public Server(String configFile) throws FileNotFoundException, IOException {
		this.configFile  = configFile;
		
		
		
		this.props = new Properties();
		
		props.load(new FileInputStream(this.configFile));
		
	}
	
	public void startServer() throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException, LdapNamingException, IOException {
		String portString;
		
		
		//this is a hack for testing.
		if (logger == null) {
			logger = Logger.getLogger(Server.class.getName());
		}
		
		logger.debug("Loading global chain...");
		this.buildGlobalChain();
		logger.debug("Global chain loaded");
		logger.debug("Loading local chain...");
		this.buildNamespaces();
		logger.debug("Local chain loaded");
		
		portString = props.getProperty("server.listener.port","");
		
		if (! portString.equals("")) {
			logger.debug("Starting server on port : " + portString);
			minaRegistry = new SimpleServiceRegistry();
			Service service = new Service( "ldap", TransportType.SOCKET, new InetSocketAddress( Integer.parseInt(portString) ) );
			minaRegistry.bind(service, new LdapProtocolProvider(this.globalChain,this.router));
			logger.debug("LDAP listener started");
		}
		
		portString = props.getProperty("server.secure.listener.port","");
		if (! portString.equals("")) {
			String keyStorePath = props.getProperty("server.secure.keystore","");
			logger.debug("Key store : " + keyStorePath);
			
			String keyStorePass = props.getProperty("server.secure.keypass","");
			KeyStore keystore;
			try {
				keystore = KeyStore.getInstance("JKS");
				keystore.load(new FileInputStream(keyStorePath), keyStorePass.toCharArray());
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(keystore, keyStorePass.toCharArray());
				SSLContext sslc = SSLContext.getInstance("SSLv3");
				sslc.init(kmf.getKeyManagers(), null, null);
				
				SSLFilter sslFilter = new SSLFilter(sslc);
				
				sslMinaRegistry = new SimpleServiceRegistry();
				Service service = new Service( "ldap", TransportType.SOCKET, new InetSocketAddress( Integer.parseInt(portString) ) );
				sslMinaRegistry.getIoAcceptor(TransportType.SOCKET).getFilterChain().addLast( "sslFilter", sslFilter );
				sslMinaRegistry.bind(service, new LdapProtocolProvider(this.globalChain,this.router));
			    
				
				
				
				
			} catch (Exception e) {
				logger.error("Could not load SSL : " + e.toString(),e);
			} 
			
		}
		
		
	}
	
	public void stopServer() {
		this.minaRegistry.unbindAll();
		for (int i=0,m=100;i<m;i++) {
			try {
				LDAPConnection con = new LDAPConnection();
				con.connect("127.0.0.1",Integer.parseInt(props.getProperty("server.listener.port","389")));
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					
				}
			} catch (LDAPException e) {
				break;
			}
		}
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
	
	public static void main(String[] args) throws Exception {
		
		String home = args[0];
		home = home.substring(0,home.lastIndexOf(File.separator));
		String loghome = home.substring(0,home.lastIndexOf(File.separator));
		
		Properties props = new Properties();
		
		
		props.load(new FileInputStream(home + "/logging.conf"));
		
		if (! props.containsKey("log4j.rootLogger")) props.put("log4j.rootLogger", "info,logfile");
		if (! props.containsKey("log4j.appender.logfile")) props.put("log4j.appender.logfile", "org.apache.log4j.RollingFileAppender");
		if (! props.containsKey("log4j.appender.logfile.File")) props.put("log4j.appender.logfile.File",loghome + "/logs/myvd.log");
		if (! props.containsKey("log4j.appender.logfile.MaxFileSize")) props.put("log4j.appender.logfile.MaxFileSize","100KB");
		if (! props.containsKey("log4j.appender.logfile.MaxBackupIndex")) props.put("log4j.appender.logfile.MaxBackupIndex","10");
		if (! props.containsKey("log4j.appender.logfile.layout")) props.put("log4j.appender.logfile.layout","org.apache.log4j.PatternLayout");
		if (! props.containsKey("log4j.appender.logfile.layout.ConversionPattern")) props.put("log4j.appender.logfile.layout.ConversionPattern","[%d][%t] %-5p %c{1} - %m%n");
		
		
		
		PropertyConfigurator.configure(props);
		
		Server.logger = Logger.getLogger(Server.class.getName());
		
		logger.info("Starting server...");
		try {
			Server server = new Server(args[0]);
			server.startServer();
			logger.info("Server started");
		} catch (Throwable t) {
			logger.error("Error starting server : " + t.toString(),t);
		}
        
		
	}

	private Properties getProps() {
		return this.props;
	}
}
