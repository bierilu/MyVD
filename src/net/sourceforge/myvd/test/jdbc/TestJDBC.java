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
package net.sourceforge.myvd.test.jdbc;

import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.util.Util;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import junit.framework.TestCase;

public class TestJDBC extends TestCase {

	Server server;
	
	protected void setUp() throws Exception {
		super.setUp();
		
		this.server = new Server(System.getenv("PROJ_DIR") + "/test/DBAdapter/vldap.props");
		this.server.startServer();
	}

	public void testStartup() {
		//do notthing
	}
	
	public void testAllUsers() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(objectClass=*)",new String[0],false);
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","domain"));
		attribs.add(new LDAPAttribute("dc","nam"));
		
		LDAPEntry entry = new LDAPEntry("dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("base entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","Boston"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjackson"));
		attribs.add(new LDAPAttribute("givenname","Jack"));
		attribs.add(new LDAPAttribute("sn","Jackson"));
		
		entry = new LDAPEntry("uid=jjackson,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("2st entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","Syracuse"));
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjeffords"));
		attribs.add(new LDAPAttribute("givenname","Jen"));
		attribs.add(new LDAPAttribute("sn","Jeffords"));
		
		entry = new LDAPEntry("uid=jjeffords,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("3rd entry failed");
		}
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	
	
	public void testSimpleSearch() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(l=NY)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		LDAPEntry entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","Boston"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjackson"));
		attribs.add(new LDAPAttribute("givenname","Jack"));
		attribs.add(new LDAPAttribute("sn","Jackson"));
		
		entry = new LDAPEntry("uid=jjackson,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("2st entry failed");
		}
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	
	public void testANDSearch() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(&(l=NY)(l=LA))",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		LDAPEntry entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	
	public void testANDObjectClassSearch() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(&(&(l=NY)(l=LA))(objectClass=inetOrgPerson))",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		LDAPEntry entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	
	public void testAllGroups() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("ou=groups,dc=compinternal,dc=com",2,"(objectClass=*)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","organizationalUnit"));
		attribs.add(new LDAPAttribute("ou","groups"));
		
		LDAPEntry entry = new LDAPEntry("ou=groups,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("base entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("uniqueMember","uid=jjeffords,dc=nam,dc=compinternal,dc=com"));
		attribs.add(new LDAPAttribute("objectClass","groupOfUniquenames"));
		attribs.add(new LDAPAttribute("cn","Admins"));
		
		
		entry = new LDAPEntry("cn=Admins,ou=groups,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		LDAPEntry entry2 = res.next();
		if (! util.compareEntry(entry,entry2)) {
			fail("1st entry failed " + entry2.toString());
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("uniqueMember","uid=jjackson,dc=nam,dc=compinternal,dc=com"));
		attribs.getAttribute("uniqueMember").addValue("uid=aalberts,dc=nam,dc=compinternal,dc=com");
		attribs.add(new LDAPAttribute("objectClass","groupOfUniqueNames"));
		attribs.add(new LDAPAttribute("cn","Users"));
		
		
		entry = new LDAPEntry("cn=Users,ou=groups,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("2st entry failed");
		}
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	
	public void testGroupMembership() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("ou=groups,dc=compinternal,dc=com",2,"(&(cn=Users)(uniquemember=uid=aalberts,dc=nam,dc=compinternal,dc=com))",new String[0],false);
		
		LDAPEntry entry;
		LDAPAttributeSet attribs;
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("uniqueMember","uid=jjackson,dc=nam,dc=compinternal,dc=com"));
		attribs.getAttribute("uniqueMember").addValue("uid=aalberts,dc=nam,dc=compinternal,dc=com");
		attribs.add(new LDAPAttribute("objectClass","groupOfUniqueNames"));
		attribs.add(new LDAPAttribute("cn","Users"));
		
		
		entry = new LDAPEntry("cn=Users,ou=groups,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("2st entry failed");
		}
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	
	
	public void testBaseSearchRoot() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",0,"(objectClass=*)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		
		attribs.add(new LDAPAttribute("objectClass","domain"));
		attribs.add(new LDAPAttribute("dc","nam"));

		
		LDAPEntry entry = new LDAPEntry("dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	
	public void testBaseSearchObject() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("uid=aalberts,dc=nam,dc=compinternal,dc=com",0,"(objectClass=*)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		LDAPEntry entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	
	public void testSubtreeFromUser() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("uid=aalberts,dc=nam,dc=compinternal,dc=com",2,"(objectClass=*)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		LDAPEntry entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
	}

}
