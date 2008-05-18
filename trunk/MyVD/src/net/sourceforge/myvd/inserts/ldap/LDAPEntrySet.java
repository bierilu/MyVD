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
package net.sourceforge.myvd.inserts.ldap;

import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.EntrySet;

import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.DN;

public class LDAPEntrySet implements EntrySet {

	LDAPInterceptor interceptor;
	ConnectionWrapper wrapper;
	LDAPSearchResults results;
	
	Entry currEntry;
	
	boolean done;
	boolean entryFetched;
	boolean isFirst;
	
	
	public LDAPEntrySet(LDAPInterceptor interceptor,ConnectionWrapper wrapper,LDAPSearchResults results) {
		this.done = false;
		this.entryFetched = true;
		this.interceptor = interceptor;
		this.wrapper = wrapper;
		this.results = results;
		this.isFirst = true;
	}
	
	public boolean hasMore() throws LDAPException {
		if (! done) {
			if (entryFetched || isFirst) {
				isFirst = false;
				return getNextLDAPEntry();
			} else {
				return true;
			}
		} else {
			return false;
		}
	}

	private boolean getNextLDAPEntry() throws LDAPException {
		try {
			if (results.hasMore()) {
				
				LDAPEntry entry = null;
				LDAPControl[] respControls = null;
				try {
					entry = results.next();
					respControls = results.getResponseControls();
				} catch (LDAPReferralException e) {
					if (this.interceptor.isIgnoreRefs()) {
						//skip this entry
						return getNextLDAPEntry();
					} else {
						//TODO create named referal?
					}
				}
				
				this.currEntry = new Entry(new LDAPEntry(interceptor.getLocalMappedDN(new DN(entry.getDN())).toString(),entry.getAttributeSet()),respControls);
				this.entryFetched = false;
				return true;
			} else {
				this.done = true;
				interceptor.returnLDAPConnection(this.wrapper);
				return false;
			}
		} catch (LDAPException e) {
			interceptor.returnLDAPConnection(wrapper);
			throw e;
		}
	}

	public Entry getNext() throws LDAPException {
		if (! done) {
			if (! entryFetched) {
				entryFetched = true;
				return this.currEntry;
			} else {
				this.hasMore();
				return this.getNext();
			}
		} else {
			return null;
		}
	}

	public void abandon() throws LDAPException {
		this.interceptor.returnLDAPConnection(this.wrapper);

	}

}
