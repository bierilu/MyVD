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

import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.Password;

import com.novell.ldap.DsmlConnection;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.SPMLConnection;
import com.novell.ldap.util.DN;

public class ConnectionWrapper {
	LDAPConnection con;
	Bool locked;
	DN bindDN;
	Password pass;
	LDAPInterceptor interceptor;
	
	
	
	public ConnectionWrapper(LDAPInterceptor interceptor) {
		this.interceptor = interceptor;
		this.locked = new Bool(false);
		this.locked.setValue(false);
		this.bindDN = null;
	}
	
	public synchronized boolean wasLocked() {
		
		synchronized (this.locked) {
			if (! this.locked.getValue()) {
				this.locked.setValue(true);
				return false;
			} else {
				return true;
			}
		}
	}
	
	public void bind(DN bindDN,Password password) throws LDAPException {
		
		
		con.bind(3,bindDN.toString(),password.getValue());
		this.bindDN = bindDN;
		this.pass = password;
	}
	
	public LDAPConnection getConnection() {
		return this.con;
	}
	
	public void reConnect() throws LDAPException {
		if (con != null && con.isConnectionAlive()) {
			con.disconnect();
		}
		
		this.con = this.createConnection();
	}
	
	private LDAPConnection createConnection() throws LDAPException {
		LDAPConnection ldapcon = null;
		switch (interceptor.type) {
			case LDAP : ldapcon = new LDAPConnection();
			            break;
			case DSMLV2 : DsmlConnection con = new DsmlConnection();
						  con.setUseSoap(interceptor.isSoap);
						  ldapcon = con;
						  break;
			case SPML : SPMLConnection spml = new SPMLConnection(interceptor.spmlImpl);
						ldapcon = spml;
						break;
			
		}
		
		
		if (ldapcon == null) {
			return null;
		} else {
			ldapcon.connect(this.interceptor.host,this.interceptor.port);
			return ldapcon;
		}
	}
	
	public synchronized void unlock() {
		synchronized (this.locked) {
			this.locked.setValue(false);
		}
	}
	
	public DN getBindDN() {
		return this.bindDN;
	}

	public void reBind() throws LDAPException {
		if (this.bindDN != null) {
			this.bind(this.bindDN,this.pass);
		}
		
	}
	
}
