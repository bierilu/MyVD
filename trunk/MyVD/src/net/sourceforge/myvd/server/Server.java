/*
 * Copyright 2008 Marc Boorshtein 
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
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.protocol.ldap.LdapProtocolProvider;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;


import net.sourceforge.myvd.protocol.ldap.mina.ldap.exception.LdapNamingException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.extended.NoticeOfDisconnect;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.mina.common.DefaultIoFilterChainBuilder;
import org.apache.mina.common.ExecutorThreadModel;
import org.apache.mina.common.IoAcceptor;
import org.apache.mina.common.IoFilterChainBuilder;
import org.apache.mina.common.IoSession;
import org.apache.mina.common.TransportType;
import org.apache.mina.common.WriteFuture;
import org.apache.mina.filter.SSLFilter;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.filter.codec.textline.TextLineCodecFactory;
import org.apache.mina.transport.socket.nio.SocketAcceptor;
import org.apache.mina.transport.socket.nio.SocketAcceptorConfig;
import org.apache.mina.transport.socket.nio.SocketSessionConfig;


import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.util.DN;

import edu.emory.mathcs.backport.java.util.concurrent.Executors;


public class Server {
	
	static Logger logger;
	
	protected static IoAcceptor tcpAcceptor;
	protected static ExecutorThreadModel threadModel = ExecutorThreadModel.getInstance( "MyVD" );
	public final static String VERSION = "0.8.3b1";
	
	String configFile;
	Properties props;
	private InsertChain globalChain;
	private Router router;

	private ServerCore serverCore;

	
	public InsertChain getGlobalChain() {
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
			getDefaultLog();
		}
		
		this.serverCore = new ServerCore(this.props);
		
		this.serverCore.startService();
		
		this.globalChain = serverCore.getGlobalChain();
		this.router = serverCore.getRouter();
		
		portString = props.getProperty("server.listener.port","");
		if (! portString.equals("")) {
			try {
				startLDAP(portString,null);
			} catch (Throwable t) {
				logger.error("Could not start LDAP listener",t);
			}
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
				DefaultIoFilterChainBuilder chain = new DefaultIoFilterChainBuilder();
		        chain.addLast( "SSL", sslFilter );
		        
		        startLDAP(portString,chain);
			} catch (Throwable t) {
				logger.error("Could not start LDAPS listener",t);
				t.printStackTrace();
			}
		        
		}
		
		
		
	}

	private static void getDefaultLog() {
		Properties props = new Properties();
		props.put("log4j.rootLogger", "info,console");
		
		//props.put("log4j.appender.console","org.apache.log4j.RollingFileAppender");
		//props.put("log4j.appender.console.File","/home/mlb/myvd.log");
		props.put("log4j.appender.console","org.apache.log4j.ConsoleAppender");
		props.put("log4j.appender.console.layout","org.apache.log4j.PatternLayout");
		props.put("log4j.appender.console.layout.ConversionPattern","[%d][%t] %-5p %c{1} - %m%n");
		
		
		
		PropertyConfigurator.configure(props);
		logger = Logger.getLogger(Server.class.getName());
	}

	private void startLDAP(String portString,IoFilterChainBuilder chainBuilder) throws LdapNamingException, IOException {
		if (! portString.equals("")) {
			logger.debug("Starting server on port : " + portString);
			
			LdapProtocolProvider protocolProvider = new LdapProtocolProvider(this.globalChain,this.router,this.props.getProperty("server.binaryAttribs","userPassword"));
			
//			 Disable the disconnection of the clients on unbind
            SocketAcceptorConfig acceptorCfg = new SocketAcceptorConfig();
            acceptorCfg.setDisconnectOnUnbind( false );
            
            acceptorCfg.setReuseAddress( true );
            
            if (chainBuilder == null) {
            	acceptorCfg.setFilterChainBuilder( new DefaultIoFilterChainBuilder() );
            } else {
            	acceptorCfg.setFilterChainBuilder( chainBuilder );
            }
            acceptorCfg.setThreadModel( threadModel );
            //acceptorCfg.getFilterChain().addLast("codec", new ProtocolCodecFilter( new TextLineCodecFactory( Charset.forName( "UTF-8" ))));
            
            ((SocketSessionConfig)(acceptorCfg.getSessionConfig())).setTcpNoDelay( true );
            
            logger.debug("Port String : " + portString);
            logger.debug("Protocol Prpvider : " + protocolProvider);
            logger.debug("AcceptorConfig : " + acceptorCfg);
            logger.debug("tcpAcceptor : " + tcpAcceptor);
            
            //tcpAcceptor = new SocketAcceptor(((int) Runtime.getRuntime().availableProcessors()) + 1,null);
            tcpAcceptor = new SocketAcceptor();
            
            //try 3 times?
            for (int i=0;i<3;i++) {
            	try {
            		tcpAcceptor.bind( new InetSocketAddress( Integer.parseInt(portString) ), protocolProvider.getHandler(), acceptorCfg );
            		break;
            	} catch (java.net.BindException e) {
            		logger.error("Could not bind to address, waiting 30 seconds to try again",e);
            		try {
						Thread.sleep(30000);
					} catch (InterruptedException e1) {
						
					}
            	}
            }
            
			
			/*minaRegistry = new SimpleServiceRegistry();
			Service service = new Service( "ldap", TransportType.SOCKET, new InetSocketAddress( Integer.parseInt(portString) ) );
			*/
			logger.debug("LDAP listener started");
		}
	}
	
	public void stopServer() {
		//this.minaRegistry.unbindAll();
		logger.info("Shutting down server");
		this.stopLDAP0(Integer.parseInt(props.getProperty("server.listener.port","389")));
		for (int i=0,m=100;i<m;i++) {
			try {
				LDAPConnection con = new LDAPConnection();
				con.connect("127.0.0.1",Integer.parseInt(props.getProperty("server.listener.port","389")));
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					
				}
			} catch (LDAPException e) {
				//logger.error("Error",e);
				break;
			}
		}
		
		this.router.shutDownRouter();
		
		logger.info("Server Stopped");
	}
	
	
	
	public static void main(String[] args) throws Exception {
		
		
		if (System.getProperty("nolog","0").equalsIgnoreCase("0")) {
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
		} else {
			getDefaultLog();
		}
		logger.info("MyVirtualDirectory Version : " + Server.VERSION);
		logger.info("Starting MyVirtualDirectory server...");
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
	
	private void stopLDAP0( int port )
    {
        try
        {
            // we should unbind the service before we begin sending the notice 
            // of disconnect so new connections are not formed while we process
            List writeFutures = new ArrayList();

            // If the socket has already been unbound as with a successful 
            // GracefulShutdownRequest then this will complain that the service
            // is not bound - this is ok because the GracefulShutdown has already
            // sent notices to to the existing active sessions
            List sessions = null;
            try
            {
                sessions = new ArrayList( tcpAcceptor.getManagedSessions( new InetSocketAddress( port ) ) );
            }
            catch ( IllegalArgumentException e )
            {
                logger.warn( "Seems like the LDAP service (" + port + ") has already been unbound." );
                return;
            }

            tcpAcceptor.unbind( new InetSocketAddress( port ) );
            if ( logger.isInfoEnabled() )
            {
            	logger.info( "Unbind of an LDAP service (" + port + ") is complete." );
            	logger.info( "Sending notice of disconnect to existing clients sessions." );
            }

            // Send Notification of Disconnection messages to all connected clients.
            if ( sessions != null )
            {
                for ( Iterator i = sessions.iterator(); i.hasNext(); )
                {
                    IoSession session = ( IoSession ) i.next();
                    writeFutures.add( session.write( NoticeOfDisconnect.UNAVAILABLE ) );
                }
            }

            // And close the connections when the NoDs are sent.
            Iterator sessionIt = sessions.iterator();
            for ( Iterator i = writeFutures.iterator(); i.hasNext(); )
            {
                WriteFuture future = ( WriteFuture ) i.next();
                future.join( 1000 );
                ( ( IoSession ) sessionIt.next() ).close();
            }
        }
        catch ( Exception e )
        {
        	logger.warn( "Failed to sent NoD.", e );
        }
        
        try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			
		}
        
    }
}
