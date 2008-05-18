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
package net.sourceforge.myvd.test.router;

import java.util.ArrayList;
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

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

public class TestChainR implements Insert {

	String name;
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		// TODO Auto-generated method stub

		this.name = name;
	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		entry.getEntry().getAttributeSet().add(new LDAPAttribute("sn","User1"));

		chain.nextAdd(entry,constraints);
	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		dn.setDN(new DN("cn=Test User," + dn.getDN().toString()));
		
		chain.nextBind(dn,pwd,constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		//TODO add test

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		dn.setDN(new DN("cn=Test User," + dn.getDN().toString()));
		chain.nextDelete(dn,constraints);
	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
			chain.nextExtendedOperations(op,constraints);

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		LDAPModification mod = new LDAPModification(LDAPModification.ADD,new LDAPAttribute("sn","Second Surname"));
		mods.add(mod);
		chain.nextModify(dn,mods,constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		attributes.clear();
		DistinguishedName newBase;
		if (chain.getRequest().containsKey("ISRENAME")) {
			newBase = new DistinguishedName("cn=Test User," + base.getDN().toString());
		} else {
			newBase = base;
		}
		chain.nextSearch(newBase,scope,filter,attributes,typesOnly,results,constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		chain.getRequest().put("ISRENAME","ISRENAME");
		dn.setDN(new DN("cn=Test User," + dn.getDN().toString()));
		chain.nextRename(dn,newRdn,deleteOldRdn,constraints);
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		chain.getRequest().put("ISRENAME","ISRENAME");
		dn.setDN(new DN("cn=Test User," + dn.getDN().toString()));
		chain.nextRename(dn,newRdn,deleteOldRdn,constraints);
		
	}
	
	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		if (! chain.getRequest().containsKey("ISRENAME")) {
			entry.getEntry().getAttributeSet().add(new LDAPAttribute("testAttrib","testVal"));
		}
		chain.nextPostSearchEntry(entry,base,scope,filter,attributes,typesOnly,constraints);
		
	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base,scope,filter,attributes,typesOnly,constraints);
		
	}

	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}
}
