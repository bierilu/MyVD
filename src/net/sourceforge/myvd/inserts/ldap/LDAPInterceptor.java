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
package net.sourceforge.myvd.inserts.ldap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.types.SessionVariables;
import net.sourceforge.myvd.util.NamingUtils;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPLocalException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

public class LDAPInterceptor implements Insert {

	String host;
	int port;
	String name;
	DN remoteBase;
	String[] explodedRemoteBase;
	String[] explodedLocalBase;
	
	String proxyDN;
	byte[] proxyPass;
	
	LDAPConnectionType type;
	
	String spmlImpl;
	
	boolean isSoap;
	
	NamingUtils utils;
	
	LDAPConnectionPool pool;
	
	public void configure(String name, Properties props,NameSpace nameSpace) throws LDAPException {
		this.name = name;
		this.host = props.getProperty("host");
		this.port = Integer.parseInt(props.getProperty("port"));
		this.remoteBase = new DN(props.getProperty("remoteBase"));
		this.explodedRemoteBase = this.remoteBase.explodeDN(false);
		this.explodedLocalBase = nameSpace.getBase().getDN().explodeDN(false);
		
		this.proxyDN = (String) props.getProperty("proxyDN","");
		this.proxyPass = props.getProperty("proxyPass","").getBytes();
		
		String type = props.getProperty("type","LDAP");
		
		if (type.equalsIgnoreCase("LDAP")) {
			this.type = LDAPConnectionType.LDAP;
		} else if (type.equalsIgnoreCase("DSMLV2")) {
			this.type = LDAPConnectionType.DSMLV2;
			this.isSoap = props.getProperty("useSOAP","true").equalsIgnoreCase("true");
		} else if (type.equalsIgnoreCase("SPML")) {
			this.type = LDAPConnectionType.SPML;
			this.spmlImpl = props.getProperty("spmlImpl","com.novell.ldap.spml.NoAuthImpl");
		} else {
			throw new LDAPLocalException("Unrecognized ldap interceptor type : " + type, LDAPException.OPERATIONS_ERROR);
		}
		
		this.pool = new LDAPConnectionPool(this, Integer.parseInt(props.getProperty("minimumConnections","5")), Integer.parseInt(props.getProperty("maximumConnections","10")), Integer.parseInt(props.getProperty("maximumRetries","5")),this.type,this.spmlImpl,this.isSoap);
		
		this.utils = new NamingUtils();
	}
	
	private ConnectionWrapper getConnection(DN bindDN,Password pass,boolean force,DN base,HashMap<Object,Object> session) throws LDAPException {
		ConnectionWrapper wrapper = null;
		
		if (((ArrayList<String>) session.get(SessionVariables.BOUND_INTERCEPTORS)).contains(this.name)) {
			wrapper = pool.getConnection(bindDN,pass,force);
		} else {
			wrapper = pool.getConnection(new DN(this.proxyDN),new Password(this.proxyPass),force);
		}
		
		if (wrapper == null) {
			throw new LDAPException("Could not get remote connection",LDAPException.SERVER_DOWN,base.toString());
		} else {
			return wrapper;
		}
	}
	
	protected void returnLDAPConnection(ConnectionWrapper wrapper) {
		pool.returnConnection(wrapper);
	}

	protected DN getRemoteMappedDN(DN dn) {
		return utils.getRemoteMappedDN(dn,explodedLocalBase,explodedRemoteBase);
	}
	
	protected DN getLocalMappedDN(DN dn) {
		return utils.getLocalMappedDN(dn,explodedRemoteBase,explodedLocalBase);
		
	}
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		
		System.out.println("binddn: " + chain.getBindDN());
		
		ConnectionWrapper wrapper = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()),chain.getBindPassword(),false,new DN(entry.getEntry().getDN()),chain.getSession());
		LDAPConnection con = wrapper.getConnection();
		
		try {
			LDAPEntry remoteEntry = new LDAPEntry(this.getRemoteMappedDN(new DN(entry.getEntry().getDN())).toString(),entry.getEntry().getAttributeSet());
			con.add(remoteEntry,constraints);
		} finally {
			this.returnLDAPConnection(wrapper);
		}
		
		

		//TODO -- Add way to continue down the chain?
	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		
		DN mappedDN = this.getRemoteMappedDN(dn.getDN());
		
		ConnectionWrapper wrapper = this.getConnection(mappedDN,pwd,true,dn.getDN(),chain.getSession());
		LDAPConnection con = wrapper.getConnection();
		
		try {
			wrapper.bind(mappedDN,pwd);
			ArrayList<String> bound = (ArrayList<String>) chain.getSession().get(SessionVariables.BOUND_INTERCEPTORS);
			bound.add(this.name);
		} finally {
			this.returnLDAPConnection(wrapper);
		}
		

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		
		ConnectionWrapper wrapper = this.getConnection(chain.getBindDN().getDN(),chain.getBindPassword(),false,dn.getDN(),chain.getSession());
		LDAPConnection con = wrapper.getConnection();
		
		try {
			con.compare(this.getRemoteMappedDN(dn.getDN()).toString(),attrib.getAttribute(),constraints);
		} finally {
			this.returnLDAPConnection(wrapper);
		}

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,LDAPConstraints constraints) throws LDAPException {
		
		ConnectionWrapper wrapper = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()),chain.getBindPassword(),false,dn.getDN(),chain.getSession());
		
		
		try {
			LDAPConnection con = wrapper.getConnection();
			con.delete(this.getRemoteMappedDN(dn.getDN()).toString(),constraints);
		} finally {
			this.returnLDAPConnection(wrapper); 
		}

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {

		ConnectionWrapper wrapper = this.getConnection(chain.getBindDN().getDN(),chain.getBindPassword(),false,new DN(),chain.getSession());
		LDAPConnection con = wrapper.getConnection();
		
		try {
			con.extendedOperation(op.getOp(),constraints);
		} finally {
			this.returnLDAPConnection(wrapper);
		}

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints) throws LDAPException {
		
		
		LDAPModification[] ldapMods = new LDAPModification[mods.size()];
		System.arraycopy(mods.toArray(),0,ldapMods,0,ldapMods.length);
		
		ConnectionWrapper wrapper = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()),chain.getBindPassword(),false,dn.getDN(),chain.getSession());
		LDAPConnection con = wrapper.getConnection();
		
		try {
			con.modify(this.getRemoteMappedDN(dn.getDN()).toString(),ldapMods,constraints);
		} finally {
			this.returnLDAPConnection(wrapper);
		}

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly,
			Results results, LDAPSearchConstraints constraints) throws LDAPException {
		
		 	 String[] attribs = new String[attributes.size()];
		
		Iterator<Attribute> it = attributes.iterator();
		for (int i=0,m=attribs.length;i<m;i++) {
			it.hasNext();
			attribs[i] = it.next().getAttribute().getName();
		}
		
		ConnectionWrapper wrapper = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()),chain.getBindPassword(),false,base.getDN(),chain.getSession());
		LDAPConnection con = wrapper.getConnection();
		
		try {
			String remoteBase = this.getRemoteMappedDN(base.getDN()).toString();
			if (remoteBase == null) {
				remoteBase = "";
			}
			LDAPSearchResults res = con.search(remoteBase,scope.getValue(),filter.getValue(),attribs,typesOnly.getValue(),constraints);
			chain.addResult(results,new LDAPEntrySet(this,wrapper,res), base, scope, filter, attributes, typesOnly, constraints);
		} finally  {
			
			this.returnLDAPConnection(wrapper);
		}
		

	}

	public String getHost() {
		return host;
	}

	public String getName() {
		return name;
	}

	public int getPort() {
		return port;
	}

	public DN getRemoteBase() {
		return remoteBase;
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		
		String oldDN = this.getRemoteMappedDN(dn.getDN()).toString();
		
		
		ConnectionWrapper wrapper = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()),chain.getBindPassword(),false,dn.getDN(),chain.getSession());
		LDAPConnection con = wrapper.getConnection();
		
		try {
			con.rename(oldDN,newRdn.getDN().toString(),deleteOldRdn.getValue());
		} finally {
			this.returnLDAPConnection(wrapper);
		}
		
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		String oldDN = this.getRemoteMappedDN(dn.getDN()).toString();
		String newPDN = this.getRemoteMappedDN(newParentDN.getDN()).toString();
		
		ConnectionWrapper wrapper = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()),chain.getBindPassword(),false,dn.getDN(),chain.getSession());
		LDAPConnection con = wrapper.getConnection();
		
		try {
			con.rename(oldDN,newRdn.getDN().toString(),newPDN,deleteOldRdn.getValue());
		} finally {
			this.returnLDAPConnection(wrapper);
		}
		
	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub
		
	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub
		
	}

}
