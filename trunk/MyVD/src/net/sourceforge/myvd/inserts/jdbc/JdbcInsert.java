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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.sql.DataSource;

import org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS;
import org.apache.commons.dbcp.datasources.SharedPoolDataSource;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.InterceptorChain;
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
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.EntryUtil;
import net.sourceforge.myvd.util.IteratorEntrySet;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchRequest;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

public class JdbcInsert implements Insert {

	public static final String MYVD_DB_CON = "MYVD_DB_CON_";
	public static final String MYVD_DB_LDAP2DB = "MYVD_DB_LDAP2DB_";
	public static final String MYVD_DB_DB2LDAP = "MYVD_DB_DB2LDAP_";
	String driver;
	String url;
	String user;
	String pwd;
	
	
	int maxCons;
	int maxIdleCons;
	
	DataSource ds;
	
	String base;
	String SQL;
	String searchSQL;
	String rdn;
	String dbRdn;
	
	String objectClass;
	
	DN baseDN;
	
	boolean addBaseToFilter;
	
	
	HashMap<String,String> ldap2db,db2ldap;
	private String name;
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		
		this.name = name;
		
		driver = props.getProperty("driver");
		url = props.getProperty("url");
		user = props.getProperty("user");
		pwd = props.getProperty("password");
		
		
		this.maxCons = Integer.parseInt(props.getProperty("maxCons","5"));
		this.maxIdleCons = Integer.parseInt(props.getProperty("maxIdleCons","5"));
		
		
		DriverAdapterCPDS pool = new DriverAdapterCPDS();
		
		try {
			pool.setDriver(driver);
		} catch (ClassNotFoundException e) {
			throw new LDAPException("Could not load JDBC Driver",LDAPException.OPERATIONS_ERROR,driver,e);
		}
		pool.setUrl(url);
		pool.setUser(user);
		pool.setPassword(pwd);
		pool.setMaxActive(maxCons);
		pool.setMaxIdle(maxIdleCons);
		
		SharedPoolDataSource tds = new SharedPoolDataSource();
        tds.setConnectionPoolDataSource(pool);
        tds.setMaxActive(maxCons);
        tds.setMaxWait(50);
        
        this.ds = tds;
		
		base = nameSpace.getBase().toString();
		
		rdn = props.getProperty("rdn");
		
		String mapping = props.getProperty("mapping");
		StringTokenizer toker = new StringTokenizer(mapping,",");
		
		this.ldap2db = new HashMap<String,String>();
		this.db2ldap = new HashMap<String,String>();
		
		while (toker.hasMoreTokens()) {
			String token = toker.nextToken();
			String ldap = token.substring(0,token.indexOf('='));
			String db = token.substring(token.indexOf('=') + 1);
			
			ldap2db.put(ldap.toLowerCase(),db.toLowerCase());
			db2ldap.put(db.toLowerCase(),ldap.toLowerCase());
			
		}
		
		this.objectClass = props.getProperty("objectClass");
		this.rdn = props.getProperty("rdn");
		this.dbRdn = ldap2db.get(rdn);
		
		this.SQL = props.getProperty("sql");
		this.searchSQL = "SELECT " + ldap2db.get(this.rdn.toLowerCase()) + " " + SQL.substring(SQL.indexOf(" FROM "));
		
		this.baseDN = new DN(base);
		
		this.addBaseToFilter = Boolean.parseBoolean(props.getProperty("addBaseToFilter","true"));

	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		Connection con = null;
		
		try {
			con = this.getCon();
			loadRequest(chain, con);
			chain.nextAdd(entry, constraints);
		} catch (Throwable t) {
			if (t instanceof LDAPException) {
				throw (LDAPException) t;
			} else {
				throw new LDAPException("Error",LDAPException.OPERATIONS_ERROR,"Error",t);
			}
			
		} finally {
			unloadRequest(chain, con);
			returnCon(con);
		}
		

	}

	private void loadRequest(InterceptorChain chain, Connection con) {
		chain.getRequest().put(JdbcInsert.MYVD_DB_CON + this.name, con);
		chain.getRequest().put(JdbcInsert.MYVD_DB_DB2LDAP + this.name, this.db2ldap.clone());
		
		chain.getRequest().put(JdbcInsert.MYVD_DB_LDAP2DB + this.name, this.ldap2db.clone());
	}

	public void returnCon(Connection con) {
		try {
			con.close();
		} catch (SQLException e) {
			
		}
		
	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		Connection con = null;
		
		try {
			con = this.getCon();
			chain.getRequest().put(JdbcInsert.MYVD_DB_CON + this.name, con);
			chain.nextBind(dn, pwd, constraints);
		} catch (Throwable t) {
			if (t instanceof LDAPException) {
				throw (LDAPException) t;
			} else {
				throw new LDAPException("Error",LDAPException.OPERATIONS_ERROR,"Error",t);
			}
			
		} finally {
			unloadRequest(chain, con);
		}

	}

	private void unloadRequest(InterceptorChain chain, Connection con) {
		chain.getRequest().remove(JdbcInsert.MYVD_DB_CON + this.name);
		returnCon(con);
		chain.getRequest().remove(JdbcInsert.MYVD_DB_DB2LDAP + this.name);
		chain.getRequest().remove(JdbcInsert.MYVD_DB_LDAP2DB + this.name);
	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		Connection con = null;
		
		try {
			con = this.getCon();
			chain.getRequest().put(JdbcInsert.MYVD_DB_CON + this.name, con);
			chain.nextDelete(dn, constraints);
		} catch (Throwable t) {
			if (t instanceof LDAPException) {
				throw (LDAPException) t;
			} else {
				throw new LDAPException("Error",LDAPException.OPERATIONS_ERROR,"Error",t);
			}
			
		} finally {
			unloadRequest(chain, con);
		}

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		Connection con = null;
		
		try {
			con = this.getCon();
			chain.getRequest().put(JdbcInsert.MYVD_DB_CON + this.name, con);
			chain.nextExtendedOperations(op, constraints);
		} catch (Throwable t) {
			if (t instanceof LDAPException) {
				throw (LDAPException) t;
			} else {
				throw new LDAPException("Error",LDAPException.OPERATIONS_ERROR,"Error",t);
			}
			
		} finally {
			unloadRequest(chain, con);
		}

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		Connection con = null;
		
		try {
			con = this.getCon();
			this.loadRequest(chain, con);
			chain.nextModify(dn, mods, constraints);
		} catch (Throwable t) {
			if (t instanceof LDAPException) {
				throw (LDAPException) t;
			} else {
				throw new LDAPException("Error",LDAPException.OPERATIONS_ERROR,"Error",t);
			}
			
		} finally {
			unloadRequest(chain, con);
		}

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		if (scope.getValue() == 0) {
			
			if (base.getDN().toString().equals(this.base)) {
				ArrayList<Entry> entries = new ArrayList<Entry>();
				
				entries.add(new Entry(EntryUtil.createBaseEntry(new DN(this.base))));
				
				chain.addResult(results,new IteratorEntrySet(entries.iterator()),base,scope,filter,attributes,typesOnly,constraints);
				return;
			} else {
				filter = addBaseToFilter(base, filter);
			}
			
			
		} else if (this.addBaseToFilter && scope.getValue() == 2 && ! base.getDN().equals(this.baseDN)) {
			filter = addBaseToFilter(base, filter);
		}
		
		Connection con = null;
		
		try {
			con = getCon();
		} catch (Exception e) {
			e.printStackTrace();
			throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,e.toString());
		}
		
		String mappedSearch;
		
		if (filter.getRoot().getType() == FilterType.PRESENCE && filter.getRoot().getName().equalsIgnoreCase("objectClass")) {
			mappedSearch = this.searchSQL;
		} else {
			StringBuffer filterString = new StringBuffer();
			this.stringFilter(filter.getRoot(),filterString);
			mappedSearch = this.searchSQL + " WHERE " + filterString.toString();
		}
		
		
		String querySQL = "SELECT * FROM (" + SQL + ") X WHERE " + this.dbRdn + " IN (" + mappedSearch + ") ORDER BY " + this.dbRdn;
		try {
			PreparedStatement ps = con.prepareStatement(querySQL);
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				chain.addResult(results,new JdbcEntrySet(con,ps,rs,this,filter,scope.getValue(),base.getDN()),base,scope,filter,attributes,typesOnly,constraints);
			} else {
				con.close();
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,e.toString());
		}
		
		
		

	}

	private Filter addBaseToFilter(DistinguishedName base, Filter filter) {
		String rdnName,rdnVal;
		
		RDN rdn = (RDN) base.getDN().getRDNs().get(0); 
		rdnName = rdn.getType();
		rdnVal = rdn.getValue();
		
		ArrayList<FilterNode> ands = new ArrayList<FilterNode>();
		ands.add(new FilterNode(FilterType.EQUALS,rdnName, rdnVal));
		try {
			ands.add((FilterNode) filter.getRoot().clone());
		} catch (CloneNotSupportedException e) {
			
		}
		FilterNode newroot = new FilterNode(FilterType.AND,ands);
		filter = new Filter(newroot);
		//System.out.println("filter : " + filter.getRoot().toString());
		return filter;
	}

	private Connection getCon() throws InstantiationException, IllegalAccessException, ClassNotFoundException, SQLException {
		
		return this.ds.getConnection();
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		Connection con = null;
		
		try {
			con = this.getCon();
			chain.getRequest().put(JdbcInsert.MYVD_DB_CON + this.name, con);
			chain.nextRename(dn, newRdn, deleteOldRdn, constraints);
		} catch (Throwable t) {
			if (t instanceof LDAPException) {
				throw (LDAPException) t;
			} else {
				throw new LDAPException("Error",LDAPException.OPERATIONS_ERROR,"Error",t);
			}
			
		} finally {
			unloadRequest(chain, con);
			
		}

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		Connection con = null;
		
		try {
			con = this.getCon();
			chain.getRequest().put(JdbcInsert.MYVD_DB_CON + this.name, con);
			chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);
		} catch (Throwable t) {
			if (t instanceof LDAPException) {
				throw (LDAPException) t;
			} else {
				throw new LDAPException("Error",LDAPException.OPERATIONS_ERROR,"Error",t);
			}
			
		} finally {
			unloadRequest(chain, con);
			
		}

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		//no need for post search entry code

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		//no need for post search complete code

	}
	
	private String stringFilter(FilterNode root, StringBuffer filter) {
        FilterType op;
        //filter.append('(');
        String comp = null;
        ArrayList<FilterNode> children;
        Iterator<FilterNode> filterIt;
        String attribName = null;
        
        boolean isFirst = true;
        
        
                op = root.getType();
                switch (op){
                    case AND:
                    		
                    		HashMap<String,ArrayList<FilterNode>> attribs = new HashMap<String,ArrayList<FilterNode>>();
                    		//first sort the nodes into "buckets"
                    		children = root.getChildren();
                        filterIt = children.iterator();
                        while (filterIt.hasNext()) {
                        		FilterNode node = filterIt.next();
                        		if (node.getType() == FilterType.AND) {
                        			ArrayList<FilterNode> ands = attribs.get("&");
                        			if (ands == null) {
                        				ands = new ArrayList<FilterNode>();
                        				attribs.put("&",ands);
                        			}
                        			ands.add(node);
                        		} else if (node.getType() == FilterType.OR) {
                        			ArrayList<FilterNode> ors = attribs.get("|");
                        			if (ors == null) {
                        				ors = new ArrayList<FilterNode>();
                        				attribs.put("|",ors);
                        			}
                        			ors.add(node);
                        		} else if (node.getType() == FilterType.NOT) {
                        			ArrayList<FilterNode> nots = attribs.get("!");
                        			if (nots == null) {
                        				nots = new ArrayList<FilterNode>();
                        				attribs.put("!",nots);
                        			}
                        			nots.add(node);
                        		} else {
                        			
                        			ArrayList<FilterNode> attribNodes = attribs.get(node.getName().toLowerCase());
                        			if (attribNodes == null) {
                        				attribNodes = new ArrayList<FilterNode>();
                        				attribs.put(node.getName(),attribNodes);
                        			}
                        			attribNodes.add(node);
                        		}
                        }
                        
                        filter.append(" ( ");
                    		
                        Iterator<String> itBuckets = attribs.keySet().iterator();
                        while (itBuckets.hasNext()) {
                        		String attrib = itBuckets.next();
                        		ArrayList<FilterNode> nodes = attribs.get(attrib);
                        		if (attrib.equals("&")) {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter);
                        				if (itNodes.hasNext()) {
                        					filter.append(" AND ");
                        				}
                        			}
                        			
                        			
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" AND ");
                        			}
                        		} else if (attrib.equals("|")) {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter);
                        				if (itNodes.hasNext()) {
                        					filter.append(" AND ");
                        				}
                        			}
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" AND ");
                        			}
                        		} else if (attrib.equals("!")) {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter);
                        				if (itNodes.hasNext()) {
                        					filter.append(" AND ");
                        				}
                        			}
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" AND ");
                        			}
                        		} else {
                        			Iterator<FilterNode> itNodes = nodes.iterator();
                        			filter.append(" ( ");
                        			while (itNodes.hasNext()) {
                        				stringFilter(itNodes.next(),filter);
                        				if (itNodes.hasNext()) {
                        					filter.append(" OR ");
                        				}
                        			}
                        			filter.append(" ) ");
                        			
                        			if (itBuckets.hasNext()) {
                        				filter.append(" AND ");
                        			}
                        		}
                        }
                        
                        filter.append(" ) ");
                    		
                        
                        
                        break;
                    case OR:
                    		filter.append(" ( ");
                        
                        children = root.getChildren();
                        filterIt = children.iterator();
                        while (filterIt.hasNext()) {
                        		stringFilter(filterIt.next(),filter);
                        		if (filterIt.hasNext()) {
                        			filter.append(" OR ");
                        		}
                        }
                        filter.append(" ) ");
                        break;
                        
                    case NOT:
                        filter.append(" NOT ( ");
                        stringFilter(root.getNot(),filter);
                        filter.append(" ) ");
                        
                        break;
                    case EQUALS:{
                    		if (root.getName().equalsIgnoreCase("objectclass")) {
                    			filter.append(" 1=1 ");
                    		} else {
	                        attribName = this.ldap2db.get(root.getName());
	                    		filter.append(attribName);
	                        filter.append("='");
	                        
	                        filter.append(root.getValue()).append('\'');
                    		}
                        
                        
                        
                        break;
                    }
                    case GREATER_THEN:{
                    		attribName = this.ldap2db.get(root.getName());
                    		filter.append(attribName);
                        filter.append(">='");
                        filter.append(root.getValue()).append('\'');
                        break;
                    }
                    case LESS_THEN:{
                    		attribName = this.ldap2db.get(root.getName());
                    		filter.append(attribName);
                        filter.append("<='");
                        filter.append(root.getValue()).append('\'');
                        break;
                        
                        
                    }
                    case PRESENCE:
                    		if (root.getName().equalsIgnoreCase("objectclass")) {
                    			filter.append(" 1=1 ");
                    		} else {
	                    		filter.append(this.ldap2db.get(root.getName()));
	                        filter.append(" IS NOT NULL ");
                    		}
                        break;
                    /*case APPROX_MATCH:
                        filter.append((String)itr.next());
                        filter.append("~=");
                        byte[] value = (byte[])itr.next();
                        filter.append(byteString(value));
                        
                        if (comp != null && itr.hasNext()) {
                        	filter.append(comp);
                        }
                        
                        break;
                    case LDAPSearchRequest.EXTENSIBLE_MATCH:
                        String oid = (String)itr.next();

                        filter.append((String)itr.next());
                        filter.append(':');
                        filter.append(oid);
                        filter.append(":=");
                        filter.append((String)itr.next());
                        
                        if (comp != null && itr.hasNext()) {
                        	filter.append(comp);
                        }
                        
                        break;*/
                    case SUBSTR:{
                    		attribName = this.ldap2db.get(root.getName());
                    		filter.append(attribName);
                        filter.append(" LIKE '");
                        boolean noStarLast = false;
                        
                        filter.append(root.getValue().replace('*','%')).append('\'');
                        
                        break;
                    }
                }
            
        
        
        
        
        if (comp != null) {
        	filter.append(')');
        }
        
        return attribName;
    }
	
	public String getName() {
		return this.name;
	}

	public HashMap<String, String> getDB2LDAPMap() {
		return this.db2ldap;
	}

	public String getRDNField() {
		return this.rdn;
	}

	public HashMap<String, String> getLDAP2DBMap() {
		return this.ldap2db;
	}

}
