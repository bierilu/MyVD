package net.sourceforge.myvd.inserts.join;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

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
import net.sourceforge.myvd.util.NamingUtils;

public class JoinAddFlatNS implements Insert {

	String name;
	String joinerName;
	
	NameSpace ns;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		HashSet joinAttribs = (HashSet) chain.getRequest().get(Joiner.MYVD_JOIN_JATTRIBS + this.joinerName);
		LDAPAttributeSet primaryAttribs = new LDAPAttributeSet(),joinedAttribs = new LDAPAttributeSet();
		
		LDAPAttributeSet toadd = entry.getEntry().getAttributeSet();
		
		Iterator it = toadd.iterator();
		
		while (it.hasNext()) {
			LDAPAttribute attrib = (LDAPAttribute) it.next();
			if (! joinAttribs.contains(attrib.getName())) {
				primaryAttribs.add(attrib);
			} else {
				joinedAttribs.add(attrib);
			}
			
			if (attrib.getName().equalsIgnoreCase("objectclass")) {
				attrib.removeValue("appPerson");
			} else if (attrib.getName().equals("uid")) {
				primaryAttribs.add(attrib);
				joinedAttribs.add(attrib);
			}
			
			
		}
		
		LDAPAttribute oc = new LDAPAttribute("objectClass","appPerson");
		joinedAttribs.add(oc);
		
		NamingUtils nameutil = new NamingUtils();
		
		DN primaryDN = nameutil.getRemoteMappedDN(new DN(entry.getEntry().getDN()), new String[] {"o=mycompany","c=us"}, new String[] {"o=enterprise"});
		
		DN joinedDN = nameutil.getRemoteMappedDN(new DN(entry.getEntry().getDN()), new String[] {"ou=people","o=mycompany","c=us"}, new String[] {"o=appdb"});
		
		LDAPEntry primary = new LDAPEntry(primaryDN.toString(),primaryAttribs); 
		LDAPEntry joined  = new LDAPEntry(joinedDN.toString(),joinedAttribs);
		
		AddInterceptorChain nchain = null;
		
		nchain = new AddInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,new Insert[0],chain.getSession(),chain.getRequest(),ns.getRouter());
		nchain.nextAdd(new Entry(primary), constraints);
		
		nchain = new AddInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,new Insert[0],chain.getSession(),chain.getRequest(),ns.getRouter());
		nchain.nextAdd(new Entry(joined),constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.ns = nameSpace;
		this.joinerName = props.getProperty("joinerName");

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public String getName() {
		return this.name;
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

}