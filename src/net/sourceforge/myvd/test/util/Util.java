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
package net.sourceforge.myvd.test.util;

import java.util.Iterator;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;

public class Util {
	public static boolean compareEntry(LDAPEntry entry1,LDAPEntry entry2) {
		if (! entry1.getDN().equals(entry2.getDN())) {
			return false;
		}
		
		LDAPAttributeSet attribs1 = entry1.getAttributeSet();
		LDAPAttributeSet attribs2 = entry2.getAttributeSet();
		
		Iterator<?> it = attribs1.iterator();
		int size = attribs2.size();
		while (it.hasNext()) {
			LDAPAttribute attrib1 = (LDAPAttribute) it.next();
			LDAPAttribute attrib2 = attribs2.getAttribute(attrib1.getName());
			
			if (attrib2 == null) {
				return false;
			}
			
			size--;
			
			String[] vals1 = attrib1.getStringValueArray();
			String[] vals2 = attrib2.getStringValueArray();
			
			if (vals2.length != vals1.length) {
				return false;
			}
			
			for (int i=0,m=vals1.length;i<m;i++) {
				boolean found = false;
				for (int j=0,n=vals2.length;j<n;j++) {
					if (vals1[i].equalsIgnoreCase(vals2[j])) {
						found = true;
					}
				}
				
				if (! found) {
					return false;
				}
			}
		}
		
		if (size != 0) {
			return false;
		}
		
		return true;
	}
}