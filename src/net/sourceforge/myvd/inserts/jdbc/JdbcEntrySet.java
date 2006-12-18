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
package net.sourceforge.myvd.inserts.jdbc;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.EntrySet;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.util.EntryUtil;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.util.DN;


public class JdbcEntrySet implements EntrySet {
	Connection con;
	PreparedStatement ps;
	ResultSet rs;
	JdbcInsert interceptor;
	Filter filter;
	boolean isFirst;
	private LDAPEntry entry;
	
	boolean hasMore;
	private DN base;
	private int scope;
	
	public JdbcEntrySet(Connection con,PreparedStatement ps,ResultSet rs,JdbcInsert interceptor,Filter filter,int scope,DN base) {
		this.con = con;
		this.ps = ps;
		this.rs = rs;
		this.interceptor = interceptor;
		this.hasMore = true;
		this.filter = filter;
		isFirst = true;
		this.base = base;
		this.scope = scope;
	}
	
	public boolean hasMore() throws LDAPException {
		if (! hasMore) {
			return false;
		} else if (entry != null) {
			return true;
		}
		
		if (isFirst) {
			isFirst = false;
			if (scope == 2 && base.equals(this.interceptor.baseDN)) {
				LDAPEntry entry = EntryUtil.createBaseEntry(this.base);
				if (filter.getRoot().checkEntry(entry)) {
					this.entry = entry;
					return true;
				}
				
			}
		}
		
		try {
			String rdnVal = rs.getString(interceptor.dbRdn);
			String newRdnVal = rdnVal;
			HashMap<String,HashSet<String>> attribs = new HashMap<String,HashSet<String>>();
			
			do {
				Iterator<String> it = interceptor.db2ldap.keySet().iterator();
				while (it.hasNext()) {
					String dbField = it.next();
					String ldapField = interceptor.db2ldap.get(dbField);
					HashSet<String> attrib = attribs.get(ldapField);
					if (attrib == null) {
						attrib = new HashSet<String>();
						attribs.put(ldapField,attrib);
					}
					String value = rs.getString(dbField);
					if (! attrib.contains(value)) {
						attrib.add(value);
					}
				}
				
			} while (rs.next() && ((newRdnVal = rs.getString(interceptor.dbRdn)).equalsIgnoreCase(rdnVal)));
			
			
			LDAPAttributeSet ldapAttribs = new LDAPAttributeSet();
			Iterator<String> it = attribs.keySet().iterator();
			while (it.hasNext()) {
				String attribName = it.next();
				HashSet vals = attribs.get(attribName);
				LDAPAttribute attrib = new LDAPAttribute(attribName);
				ldapAttribs.add(attrib);
				Iterator<String> valIt = vals.iterator();
				while (valIt.hasNext()) {
					attrib.addValue(valIt.next());
				}
			}
			
			ldapAttribs.add(new LDAPAttribute("objectClass",this.interceptor.objectClass));
			
			LDAPEntry tmpentry = new LDAPEntry(interceptor.rdn + "=" + rdnVal + "," + interceptor.base,ldapAttribs);
			
			boolean toReturn = false;
			if (filter.getRoot().checkEntry(tmpentry)) {
				this.entry = tmpentry;
				toReturn = true;
			} 
			
			if (newRdnVal.equalsIgnoreCase(rdnVal)) {
				this.hasMore = false;
				con.close();
			} 
			
			if (! toReturn) {
				return this.hasMore();
			}
			
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			try {
				con.close();
			} catch (SQLException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,e.toString());
		}
	}

	public Entry getNext() throws LDAPException {
		LDAPEntry toReturn = this.entry;
		this.entry = null;
		return new Entry(toReturn);
	}

	public void abandon() throws LDAPException {
		try {
			con.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
