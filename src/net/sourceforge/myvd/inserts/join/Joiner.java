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
package net.sourceforge.myvd.inserts.join;


import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;



import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;

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
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.NamingUtils;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

public class Joiner implements Insert {
	
	public static final String PRIMARY = "PRIMARY";
	
	public static final String JOINED = "JOINED";
	
	public static final Attribute ALL_ATTRIBS = new Attribute("*");
	
	DN primaryNamespace;
	DN joinedNamespace;
	DN localNameSpace;
	
	String[] explodedPrimaryNamespace;
	String[] explodedJoinedNamespace;
	String[] explodedLocalNameSpace;
	
	ArrayList<Attribute> joinFilterAttribs;
	
	NamingUtils util;
	
	NameSpace ns;
	
	HashSet<String> joinedAttrbutes;
	
	String key;
	String filterKey;
	String primaryFilterKey;
	String joinedFilterKey;
	String attributesKey;
	String baseKey;
	String scopeKey;
	String primaryAttribsKey;
	String joinedAttribsKey;
	
	FilterNode joinFilter;
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.primaryNamespace = new DN(props.getProperty("primaryNamespace"));
		this.explodedPrimaryNamespace = this.primaryNamespace.explodeDN(false);
		
		this.joinedNamespace = new DN(props.getProperty("joinedNamespace"));
		this.explodedJoinedNamespace = this.joinedNamespace.explodeDN(false);
		
		this.localNameSpace = new DN(nameSpace.getBase().getDN().toString());
		this.explodedLocalNameSpace = this.localNameSpace.explodeDN(false);
		
		this.joinedAttrbutes = new HashSet<String>();
		StringTokenizer toker = new StringTokenizer(props.getProperty("joinedAttributes"),",");
		while (toker.hasMoreTokens()) {
			this.joinedAttrbutes.add(toker.nextToken().toLowerCase());
		}
		
		if (! this.joinedAttrbutes.contains("objectclass")) {
			this.joinedAttrbutes.add("objectclass");
		}
	
		this.joinFilter = (new Filter(props.getProperty("joinFilter"))).getRoot();
		
		this.joinFilterAttribs = new ArrayList<Attribute>();
		getFilterAttributes(this.joinFilter,this.joinFilterAttribs);
		
		
		
		key = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_KEY";
		filterKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_FILTER_KEY";
		primaryFilterKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_PRIMARY_FILTER_KEY";
		joinedFilterKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_JOINED_FILTER_KEY";
		attributesKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_ATTRIBUTES_KEY";
		baseKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_BASE_KEY";
		scopeKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_SCOPE_KEY";
		primaryAttribsKey = name + "." + nameSpace.getBase().getDN().toString() + ".PRIMARY_ATTRIBS_KEY";
		joinedAttribsKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_ATTRIBS_KEY";
		
		util = new NamingUtils();
		this.ns = nameSpace;
	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		boolean primaryBindFailed = false;
		BindInterceptorChain bindChain = new BindInterceptorChain(chain.getBindDN(),chain.getBindPassword(),ns.getRouter().getGlobalChain().length,ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),ns.getRouter());
		int trys = 1;
		try {
			bindChain.nextBind(new DistinguishedName(util.getRemoteMappedDN(dn.getDN(),this.explodedLocalNameSpace,this.explodedPrimaryNamespace)),pwd,constraints);
		} catch (LDAPException e) {
			primaryBindFailed = true;
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				throw e;
			}
		}
		
		SearchInterceptorChain searchChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),ns.getRouter().getGlobalChain().length,ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),ns.getRouter());
		Results res = new Results(new Insert[0]);
		ArrayList<Attribute> attribs = new ArrayList<Attribute>();
		attribs.add(new Attribute("joinedDNs"));
		searchChain.nextSearch(dn,new Int(0),new Filter("(objectClass=*)"),attribs,new Bool(false),res,new LDAPSearchConstraints());
		
		res.start();
		if (! res.hasMore() && primaryBindFailed) {
			throw new LDAPException("Could not bind to any services",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
		}
		
		LDAPEntry entry = res.next().getEntry();
		res.finish();
		
		LDAPAttribute joinDNs = entry.getAttribute("joinedDNs");
		if (joinDNs == null) {
			if (primaryBindFailed) {
				throw new LDAPException("Could not bind to any services",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
			}
		} else {
			String[] dns = joinDNs.getStringValueArray();
			for (int i=0,m=dns.length;i<m;i++) {
				bindChain = new BindInterceptorChain(chain.getBindDN(),chain.getBindPassword(),ns.getRouter().getGlobalChain().length,ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),ns.getRouter());
				try {
					bindChain.nextBind(new DistinguishedName(dns[i]),pwd,constraints);
				} catch (LDAPException e) {
					if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
						throw e;
					}
					trys++;
				}
			}
			
			if (trys == dns.length + 1) {
				throw new LDAPException("Could not bind to any services",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
			}
		}

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

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

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		chain.getRequest().put(filterKey,filter);
		chain.getRequest().put(attributesKey,attributes);
		chain.getRequest().put(baseKey,base);
		chain.getRequest().put(scopeKey,scope);
		
		ArrayList<Attribute> primaryAttribsToUse = new ArrayList<Attribute>();
		primaryAttribsToUse.addAll(attributes);
		
		ArrayList<Attribute> joinedAttribsToUse = new ArrayList<Attribute>();
		
		Iterator<String> it = this.joinedAttrbutes.iterator();
		while (it.hasNext()) {
			Attribute attrib = new Attribute(it.next());
			if (attributes.contains(attrib)) {
				joinedAttribsToUse.add(attrib);
			}
		}
		
		//this ensures that if there were specific attributes requested, all the joined attrbutes will not be included
		if (joinedAttribsToUse.size() == 0 && primaryAttribsToUse.size() != 0) {
			joinedAttribsToUse.add(new Attribute("1.1"));
		}
		
		if (primaryAttribsToUse.size() != 0 && ! primaryAttribsToUse.contains(ALL_ATTRIBS)) {
			Iterator<Attribute> attribIt = joinFilterAttribs.iterator();
			while (attribIt.hasNext()) {
				Attribute attrib = attribIt.next();
				if (! primaryAttribsToUse.contains(attrib)) {
					primaryAttribsToUse.add(attrib);
				}
			}
		}
		
		if (joinedAttribsToUse.size() != 0 && ! joinedAttribsToUse.contains(ALL_ATTRIBS)) {
			Iterator<Attribute> attribIt = joinFilterAttribs.iterator();
			while (attribIt.hasNext()) {
				Attribute attrib = attribIt.next();
				if (! joinedAttribsToUse.contains(attrib)) {
					joinedAttribsToUse.add(attrib);
				}
			}
		}
		
		
		
		Filter primaryFilter=null, joinedFilter=null;
		FilterNode node;
		
		try {
			node = trimPrimaryFilter(filter.getRoot(),primaryAttribsToUse);
			if (node == null) {
				primaryFilter = new Filter("(objectClass=*)");
				
			} else {
				primaryFilter = new Filter(node);
			}
			
			
			node = trimJoinedFilter(filter.getRoot(),joinedAttribsToUse);
			if (node == null) {
				joinedFilter = new Filter("(objectClass=*)");
			} else {
				joinedFilter = new Filter(node);
			}

		} catch (CloneNotSupportedException e) {
			//can't happen
		}
		
		
		
		
		
		chain.getRequest().put(primaryFilterKey,primaryFilter);
		chain.getRequest().put(joinedFilterKey,joinedFilter);
		chain.getRequest().put(primaryAttribsKey,primaryAttribsToUse);
		chain.getRequest().put(joinedAttribsKey,joinedAttribsToUse);
		
		
		int primaryWeight = primaryFilter.getRoot().getWeight();
		int joinedWeight = joinedFilter.getRoot().getWeight();
		
		
		DN newSearchBase;
		Filter filterToUse;
		ArrayList<Attribute> attribsToUse;
		
		if (primaryWeight >= joinedWeight) {
			newSearchBase = util.getRemoteMappedDN(base.getDN(),this.explodedLocalNameSpace,this.explodedPrimaryNamespace);
			filterToUse = primaryFilter;
			attribsToUse = primaryAttribsToUse;
			chain.getRequest().put(key,PRIMARY);
		} else {
			newSearchBase = util.getRemoteMappedDN(base.getDN(),this.explodedLocalNameSpace,this.explodedJoinedNamespace);
			filterToUse = joinedFilter;
			attribsToUse = joinedAttribsToUse;
			chain.getRequest().put(key,JOINED);
		}
		
		
		
		JoinerEntrySet es = new JoinerEntrySet(ns.getRouter(),chain,new DistinguishedName(newSearchBase),scope,filterToUse,attribsToUse,typesOnly,constraints);
		results.addResult(chain,es,new DistinguishedName(newSearchBase),scope,filterToUse,attributes,typesOnly,constraints,ns.getChain());
		
		

	}

	private FilterNode trimJoinedFilter(FilterNode root,ArrayList<Attribute> attribs) throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				if (this.joinedAttrbutes.contains(root.getName().toLowerCase())) {
					newNode = (FilterNode) root.clone();
					Attribute attribReq = new Attribute(newNode.getName());
					if (attribs.size() != 0 && ! attribs.contains(ALL_ATTRIBS) && ! attribs.contains(attribReq)) {
						attribs.add(attribReq);
					}
					return newNode;
				} else {
					return null;
				}
				
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					FilterNode node = trimJoinedFilter(it.next(),attribs);
					if (node == null) {
						return null;
					}
					newChildren.add(node);
				}
				
				if (newChildren.size() == 0) {
					return null;
				} else if (newChildren.size() == 1) {
					return newChildren.get(0);
				} else {
					newNode = new FilterNode(joinFilter.getType(),newChildren);
					return newNode;
				}
				
				
			case NOT:
				FilterNode node = trimJoinedFilter(root.getNot(),attribs);
				if (node == null) {
					return null;
				}
				return new FilterNode(node);
		}
		
		return null;
		
	}

	private FilterNode trimPrimaryFilter(FilterNode root,ArrayList<Attribute> attribs) throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				if (root.getName().toLowerCase().equals("objectclass") || ! this.joinedAttrbutes.contains(root.getName().toLowerCase())) {
					newNode = (FilterNode) root.clone();
					Attribute attribReq = new Attribute(newNode.getName());
					if (attribs.size() != 0 && ! attribs.contains(ALL_ATTRIBS) && ! attribs.contains(attribReq)) {
						attribs.add(attribReq);
					}
					return newNode;
				} else {
					return null;
				}
				
				
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					FilterNode node = trimPrimaryFilter(it.next(),attribs);
					if (node == null) {
						return null;
					}
					newChildren.add(node);
				}
				
				if (newChildren.size() == 0) {
					return null;
				} else if (newChildren.size() == 1) {
					return newChildren.get(0);
				} else {
					newNode = new FilterNode(root.getType(),newChildren);
					return newNode;
				}
				
				
			case NOT:
				FilterNode node = trimPrimaryFilter(root.getNot(),attribs);
				if (node == null) {
					return null;
				}
				return new FilterNode(node);
		}
		
		return null;
		
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

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		FilterNode newJoinFilter = null;
		Int joinCount = new Int(0);
		Int joinAttribCount = new Int(0);
		try {
			
			newJoinFilter = createJoinFilter(this.joinFilter,entry.getEntry(),joinCount,joinAttribCount);
		} catch (CloneNotSupportedException e) {
			//not possible
		}
		
		boolean isPrimary = chain.getRequest().get(key).equals(PRIMARY);
		Filter originalFilter = (Filter) chain.getRequest().get(filterKey);
		if (newJoinFilter == null || (joinCount.getValue() != 0 && joinCount.getValue() == joinAttribCount.getValue()) ) {
			if (! isPrimary) {
				//TODO add way to skip entries
				entry.setReturnEntry(false);
				return;
				//there's no reason to continue down the chain
			} else {
				//its a primary entry, make sure it passes the original filter
				if (! originalFilter.getRoot().checkEntry(entry.getEntry())) {
					entry.setReturnEntry(false);
					
					return;
					//there's no reason to continue down the chain
				} else {
					//we're done
					entry.setDN(util.getLocalMappedDN(new DN(entry.getEntry().getDN()),this.explodedPrimaryNamespace,this.explodedLocalNameSpace));
					return;
				}
			}
		}
		
		ArrayList<FilterNode> joiningFilterConds = new ArrayList<FilterNode>();
		joiningFilterConds.add(newJoinFilter);
		
		if (isPrimary) {
			joiningFilterConds.add(((Filter) chain.getRequest().get(joinedFilterKey)).getRoot());
		} else {
			joiningFilterConds.add(((Filter) chain.getRequest().get(primaryFilterKey)).getRoot());
		}
		
		FilterNode finalFilterNode = new FilterNode(FilterType.AND,joiningFilterConds);
		
		Filter finalFilter = new Filter(finalFilterNode);
			
		DistinguishedName origBase = (DistinguishedName) chain.getRequest().get(baseKey);
		Int origScope = (Int) chain.getRequest().get(scopeKey);
		
		DistinguishedName useBase;
		
		if (isPrimary) {
			useBase = new DistinguishedName(this.util.getRemoteMappedDN(origBase.getDN(),this.explodedLocalNameSpace,this.explodedJoinedNamespace));
		} else {
			useBase = new DistinguishedName(this.util.getRemoteMappedDN(origBase.getDN(),this.explodedLocalNameSpace,this.explodedPrimaryNamespace));
		}
		
		SearchInterceptorChain searchChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),ns.getRouter().getGlobalChain().length,ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),ns.getRouter());
		Results res = new Results(new Insert[0],0);
		
		ArrayList<Attribute> attribsToUse;
		
		if (isPrimary) {
			attribsToUse = (ArrayList<Attribute>) chain.getRequest().get(joinedAttribsKey);
		} else {
			attribsToUse = (ArrayList<Attribute>) chain.getRequest().get(primaryAttribsKey);
		}
		searchChain.nextSearch(useBase,origScope,finalFilter,attribsToUse,typesOnly,res,constraints);
		
		res.start();
		boolean first = true;
		
		if (isPrimary) {
			entry.setDN(util.getLocalMappedDN(new DN(entry.getEntry().getDN()),this.explodedPrimaryNamespace,this.explodedLocalNameSpace));
		}
		
		while (res.hasMore()) {
			Entry jentry = res.next();
			if (! isPrimary) {
				
				LDAPEntry orig = entry.getEntry();
				entry.setEntry(new LDAPEntry(util.getLocalMappedDN(new DN(jentry.getEntry().getDN()),this.explodedJoinedNamespace,this.explodedLocalNameSpace).toString(),jentry.getEntry().getAttributeSet()));
				jentry.setEntry(orig);
				res.finish();
			} 
			
			 
			Iterator<String> it = this.joinedAttrbutes.iterator();
			while (it.hasNext()) {
				String name = it.next();
				LDAPAttribute attrib = jentry.getEntry().getAttribute(name);
				if (attrib != null) {
					LDAPAttribute currAttrib = entry.getEntry().getAttributeSet().getAttribute(name);
					
					if (currAttrib != null) {
						byte[][] vals = attrib.getByteValueArray();
						for (int i=0,m=vals.length;i<m;i++) {
							currAttrib.addValue(vals[i]);
						}
						
					} else {
						entry.getEntry().getAttributeSet().add(attrib);
					}
					
				}
			}
			
			LDAPAttribute attrib = entry.getEntry().getAttribute("joinedDNs");
			if (attrib == null) {
				attrib = new LDAPAttribute("joinedDNs");
				entry.getEntry().getAttributeSet().add(attrib);
			}
			attrib.addValue(jentry.getEntry().getDN());
		}
		
		if (! originalFilter.getRoot().checkEntry(entry.getEntry())) {
			//filter doesn't match, lets ditch it
			entry.setReturnEntry(false);
		}
		
		
		
	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}
	
	public FilterNode createJoinFilter(FilterNode joinFilter,LDAPEntry entry, Int joinCount, Int noAttribCount) throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (joinFilter.getType()) {
			case PRESENCE :
			case SUBSTR:
				newNode = (FilterNode) joinFilter.clone();
				return newNode;
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				String filterVal = joinFilter.getValue();
				if (filterVal.startsWith("ATTR.")) {
					joinCount.setValue(joinCount.getValue() + 1);
					String attribName = filterVal.substring(filterVal.indexOf('.') + 1);
					LDAPAttribute attrib = entry.getAttribute(attribName);
					if (attrib == null) {
						noAttribCount.setValue(noAttribCount.getValue() + 1);
						//return null;
						return new FilterNode(joinFilter.getType(),joinFilter.getName(),"DOESNOTEXIST");
					}
					
					String val = attrib.getStringValue();
					if (val == null) {
						noAttribCount.setValue(noAttribCount.getValue() + 1);
						return new FilterNode(joinFilter.getType(),joinFilter.getName(),"DOESNOTEXIST");
					}
					newNode = new FilterNode(joinFilter.getType(),joinFilter.getName(),val);
					
				} else {
					newNode = new FilterNode(joinFilter.getType(),joinFilter.getName(),joinFilter.getValue());
				}
				
				return newNode;
				
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = joinFilter.getChildren().iterator();
				while (it.hasNext()) {
					FilterNode node = createJoinFilter(it.next(),entry,joinCount,noAttribCount);
					if (node == null) {
						return null;
					}
					newChildren.add(node);
				}
				
				
				newNode = new FilterNode(joinFilter.getType(),newChildren);
				return newNode;
				
			case NOT:
				FilterNode node = createJoinFilter(joinFilter.getNot(),entry,joinCount,noAttribCount);
				if (node == null) {
					return null;
				}
				return new FilterNode(node);
		}
		
		return null;
	}
	
	public void getFilterAttributes(FilterNode root,ArrayList<Attribute> attribs)  {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
				
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				Attribute attrib = new Attribute(root.getName());
				if (! attribs.contains(attrib)) {
					attribs.add(attrib);
				}
				break;
				
			case AND:
			case OR:
				
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					getFilterAttributes(it.next(),attribs);
				}
				
				break;
				
			case NOT:
				getFilterAttributes(root.getNot(),attribs);
				break;
		}
		
		
	}

}
