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
import java.util.Iterator;

import net.sourceforge.myvd.types.Password;

import com.novell.ldap.LDAPException;
import com.novell.ldap.util.DN;

public class LDAPConnectionPool {
	ArrayList<ConnectionWrapper> pool;
	
	int maxRetries;
	int maxCons;
	int minCons;
	
	LDAPConnectionType type;
	
	private LDAPInterceptor interceptor;
	
	public LDAPConnectionPool(LDAPInterceptor interceptor,int minCons,int maxCons,int maxRetries, LDAPConnectionType type,String spmlImpl,boolean isSOAP) throws LDAPException {
		this.interceptor = interceptor;
		
		this.minCons = minCons;
		this.maxCons = maxCons;
		this.maxRetries = maxRetries;
		
		this.type = type;
		
		this.pool = new ArrayList<ConnectionWrapper>();
		
		for (int i=0;i<minCons;i++) {
			ConnectionWrapper wrapper = new ConnectionWrapper(this.interceptor);
			wrapper.unlock();
			wrapper.reConnect();
			this.pool.add(wrapper);
		}
		
	}
	
	public ConnectionWrapper getConnection(DN bindDN,Password pass,boolean force) throws LDAPException {
		return this.getConnection(bindDN,pass,force,0);
	}
	
	public ConnectionWrapper getConnection(DN bindDN,Password pass,boolean force,int trys) throws LDAPException {
		
		if (trys >= this.maxRetries) {
			return null;
		}
		
		Iterator<ConnectionWrapper> it = this.pool.iterator();
		boolean wasfound = false;
		
		while (it.hasNext()) {
			ConnectionWrapper wrapper = it.next();
			
			//See if the connection is locked
			if (wrapper.wasLocked()) {
				continue;
			}
			
			//if there is an available connection, make sure to make a note
			wasfound = true;
			
			//if we are binding, we want to return the connection
			if (force) {
				return wrapper;
			}
			
			//check to see if the currnt connection has the right binddn
			if ((wrapper.getBindDN() == null && bindDN.toString() == null) || (wrapper.getBindDN() != null && bindDN.equals(wrapper.getBindDN()))) {
				return wrapper;
			}
			
			//we have not yet found a connection
			//so we can re-lock the connection
			wrapper.unlock();
		}
		
		if (wasfound) {
			it = this.pool.iterator();
			
			
			while (it.hasNext()) {
				ConnectionWrapper wrapper = it.next();
				
				//See if the connection is locked
				if (wrapper.wasLocked()) {
					continue;
				}
				
				if (wrapper.getBindDN() != null && bindDN.toString().equals(wrapper.getBindDN().toString())) {
					return wrapper;
				} else {
					try {
						wrapper.bind(bindDN,pass);
						return wrapper;
					} catch (LDAPException e) {
						wrapper.unlock();
						wrapper.reBind();
						throw e;
					}
				}
			}
		}
		
		if (this.maxCons <= this.pool.size()) {
			ConnectionWrapper wrapper = new ConnectionWrapper(this.interceptor);
			wrapper.wasLocked();
			wrapper.reConnect();
			//If this is a bind, we only want to do it once
			if (! force) {
				wrapper.bind(bindDN,pass);
			}
			this.pool.add(wrapper);
			return wrapper;
		} else {
			this.waitForConnection();
			return this.getConnection(bindDN,pass,force,trys + 1);
		}
		
	}
	
	
	private synchronized void waitForConnection() {
		
		try {
			this.wait(1000);
		} catch (InterruptedException e) {
			//dont care
		}
	}
	
	public synchronized void returnConnection(ConnectionWrapper con) {
		con.unlock();
		this.notifyAll();
	}
}
