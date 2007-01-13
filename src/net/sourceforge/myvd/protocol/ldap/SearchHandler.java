package net.sourceforge.myvd.protocol.ldap;

/*
 *   Copyright 2004 The Apache Software Foundation
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */


import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.NoSuchElementException;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

import org.apache.ldap.common.exception.LdapException;
import org.apache.ldap.common.filter.BranchNode;
import org.apache.ldap.common.filter.ExprNode;
import org.apache.ldap.common.filter.FilterVisitor;
import org.apache.ldap.common.message.LdapResultImpl;
import org.apache.ldap.common.message.ReferralImpl;
import org.apache.ldap.common.message.ResultCodeEnum;
import org.apache.ldap.common.message.SearchRequest;
import org.apache.ldap.common.message.SearchResponseDone;
import org.apache.ldap.common.message.SearchResponseDoneImpl;
import org.apache.ldap.common.message.SearchResponseEntry;
import org.apache.ldap.common.message.SearchResponseEntryImpl;
import org.apache.ldap.common.message.SearchResponseReference;
import org.apache.ldap.common.message.SearchResponseReferenceImpl;
import org.apache.ldap.common.util.ArrayUtils;
import org.apache.ldap.common.util.ExceptionUtils;
import org.apache.mina.protocol.ProtocolSession;
import org.apache.mina.protocol.handler.MessageHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchRequest;

/**
 * A handler for processing search requests.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 231083 $
 */
public class SearchHandler implements MessageHandler,LdapInfo
{
    private static final Logger LOG = LoggerFactory.getLogger( SearchHandler.class );
    private static final String DEREFALIASES_KEY = "java.naming.ldap.derefAliases";

    Insert[] globalChain;
    Router router;

    
    
    
    
    public void messageReceived( ProtocolSession session, Object request )
    {
        LdapContext ctx;
        SearchRequest req = ( SearchRequest ) request;
        NamingEnumeration list = null;

        // check the attributes to see if a referral's ref attribute is included
        String[] ids = null;
        Collection retAttrs = new HashSet();
        retAttrs.addAll( req.getAttributes() );

        if( retAttrs.size() > 0 && !retAttrs.contains( "ref" ) )
        {
            retAttrs.add( "ref" );
            ids = ( String[] ) retAttrs.toArray( ArrayUtils.EMPTY_STRING_ARRAY );
        }
        else if( retAttrs.size() > 0 )
        {
            ids = ( String[] ) retAttrs.toArray( ArrayUtils.EMPTY_STRING_ARRAY );
        }

        // prepare all the search controls
        SearchControls controls = new SearchControls();
        /*controls.setCountLimit( req.getSizeLimit() );
        controls.setTimeLimit( req.getTimeLimit() );
        controls.setSearchScope( req.getScope().getValue() );
        controls.setReturningObjFlag( req.getTypesOnly() );
        controls.setReturningAttributes( ids );
        controls.setDerefLinkFlag( true );*/

        try
        {
            

        	HashMap userSession = null;
        	
        	userSession = (HashMap) session.getAttribute("MYVD_SESSION");
            DistinguishedName bindDN = (DistinguishedName) session.getAttribute("MYVD_BINDDN");
            Password pass = (Password) session.getAttribute("MYVD_BINDPASS");
            
            if (bindDN == null) {
            	bindDN = new DistinguishedName("");
            	pass = new Password();
            }
            
            Results res = new Results(this.globalChain);
            StringBuffer buff = new StringBuffer();
            
            req.getFilter().printToBuffer(buff);
            
            String stringFilter = buff.toString();
			//System.out.println("Filter b: \"" + stringFilter + "\"");
			stringFilter = stringFilter.replaceAll("[|] ","|");
			stringFilter = stringFilter.replaceAll("[)] ",")");
			stringFilter = stringFilter.replaceAll("[&] ","&");
			stringFilter = stringFilter.replaceAll("[!] ","!");
			//System.out.println("Filter a: \"" + stringFilter + "\"");
            
			Filter filter = new Filter(stringFilter.trim()); 
            
            Iterator it = req.getAttributes().iterator();
            ArrayList<net.sourceforge.myvd.types.Attribute> reqAttribs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
            
            while (it.hasNext()) {
            	reqAttribs.add(new net.sourceforge.myvd.types.Attribute(it.next().toString()));
            }
            
            DistinguishedName base = new DistinguishedName(req.getBase() == null ? "" : req.getBase()); 
            
            SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,new HashMap(),this.router);
            chain.nextSearch(base,new Int(req.getScope().getValue()),filter,reqAttribs,new Bool(req.getTypesOnly()),res,new LDAPSearchConstraints());
            
            res.start();
            
            if( res.hasMore() )
            {
                it = new SearchResponseIterator( req, res );
                while( it.hasNext() )
                {
                    session.write( it.next() );
                }

                return;
            }
            else
            {
                
                SearchResponseDone resp = new SearchResponseDoneImpl( req.getMessageId() );
                resp.setLdapResult( new LdapResultImpl( resp ) );
                resp.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
                resp.getLdapResult().setMatchedDn( req.getBase() );
                it = Collections.singleton( resp ).iterator();

                while( it.hasNext() )
                {
                    session.write( it.next() );
                }

                return;
            }
        }
        catch( LDAPException e )
        {
            String msg = e.toString();

            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + req + ":\n" + ExceptionUtils.getStackTrace( e );
            }

            SearchResponseDone resp = new SearchResponseDoneImpl( req.getMessageId() );
            ResultCodeEnum rc = null;

            
            rc = ResultCodeEnum.getResultCodeEnum(e.getResultCode());
            
            if (rc == null) {
            	rc = ResultCodeEnum.OPERATIONSERROR;
            }
            
            
            resp.setLdapResult( new LdapResultImpl( resp ) );
            resp.getLdapResult().setResultCode( rc );
            resp.getLdapResult().setErrorMessage( msg );

            if( e.getMatchedDN() != null )
            {
                resp.getLdapResult().setMatchedDn( e.getMatchedDN() );
            }
            else
            {
                resp.getLdapResult().setMatchedDn( "" );
            }

            Iterator it = Collections.singleton( resp ).iterator();

            while( it.hasNext() )
            {
                session.write( it.next() );
            }
        } catch (Throwable t) {
        	t.printStackTrace();
            String msg = "failed to search "  + t.toString();
            SearchResponseDone resp = new SearchResponseDoneImpl( req.getMessageId() );
            ResultCodeEnum rc = null;
            
                msg += ":\n" + ExceptionUtils.getStackTrace( t );
            

            ResultCodeEnum code;

            
                code = ResultCodeEnum.OPERATIONSERROR;
            

            resp.getLdapResult().setResultCode( code );
            resp.getLdapResult().setErrorMessage( msg );
            

            session.write( resp );
            return;
        
    }
    }


    
    
    SearchResponseDone getResponse( SearchRequest req, NamingException e )
    {
        String msg = "failed on search operation";

        if ( LOG.isDebugEnabled() )
        {
            msg += ":\n" + req + ":\n" + ExceptionUtils.getStackTrace( e );
        }

        SearchResponseDone resp = new SearchResponseDoneImpl( req.getMessageId() );

        ResultCodeEnum rc = null;

        if( e instanceof LdapException )
        {
            rc = ( ( LdapException ) e ).getResultCode();
        }
        else
        {
            rc = ResultCodeEnum.getBestEstimate( e, req.getType() );
        }

        resp.setLdapResult( new LdapResultImpl( resp ) );

        resp.getLdapResult().setResultCode( rc );

        resp.getLdapResult().setErrorMessage( msg );

        if( e.getResolvedName() != null )
        {
            resp.getLdapResult().setMatchedDn( e.getResolvedName().toString() );
        }
        else
        {
            resp.getLdapResult().setMatchedDn( "" );
        }

        return resp;
    }
    
    SearchResponseDone getResponse( SearchRequest req, LDAPException e )
    {
        String msg = "failed on search operation";

        if ( LOG.isDebugEnabled() )
        {
            msg += ":\n" + req + ":\n" + ExceptionUtils.getStackTrace( e );
        }

        SearchResponseDone resp = new SearchResponseDoneImpl( req.getMessageId() );

        ResultCodeEnum rc = null;

        
        rc = ResultCodeEnum.getResultCodeEnum(e.getResultCode());
        

        resp.setLdapResult( new LdapResultImpl( resp ) );

        resp.getLdapResult().setResultCode( rc );

        resp.getLdapResult().setErrorMessage( msg );

        if( e.getMatchedDN() != null )
        {
            resp.getLdapResult().setMatchedDn( e.getMatchedDN() );
        }
        else
        {
            resp.getLdapResult().setMatchedDn( "" );
        }

        return resp;
    }

    class SearchResponseIterator implements Iterator
    {
        private final SearchRequest req;

        private final Results underlying;

        private SearchResponseDone respDone;

        private boolean done = false;

        private Object prefetched;

        /**
         * Creates a search response iterator for the resulting enumeration
         * over a search request.
         *
         * @param req the search request to generate responses to
         * @param underlying the underlying JNDI enumeration containing SearchResults
         */
        public SearchResponseIterator( SearchRequest req,
        		Results underlying )
        {
            this.req = req;
            this.underlying = underlying;

            try
            {
                if( underlying.hasMore() )
                {
                    
                	SearchResult result = marshall(underlying);

                	
                	
                    /*
                     * Now we have to build the prefetched object from the 'result'
                     * local variable for the following call to next()
                     */
                    Attribute ref = result.getAttributes().get( "ref" );

                    if( ref == null || ref.size() > 0 )
                    {
                        SearchResponseEntry respEntry;

                        respEntry = new SearchResponseEntryImpl( req.getMessageId() );

                        respEntry.setAttributes( result.getAttributes() );

                        respEntry.setObjectName( result.getName() );

                        prefetched = respEntry;
                    }
                    else
                    {
                        SearchResponseReference respRef;

                        respRef = new SearchResponseReferenceImpl( req.getMessageId() );

                        respRef.setReferral( new ReferralImpl( respRef ) );

                        for( int ii = 0; ii < ref.size(); ii ++ )
                        {
                            String url;

                            try
                            {
                                url = ( String ) ref.get( ii );

                                respRef.getReferral().addLdapUrl( url );
                            }
                            catch( NamingException e )
                            {
                                try
                                {
                                    underlying.finish();
                                }
                                catch( Throwable t )
                                {
                                }

                                prefetched = null;

                                respDone = getResponse( req, e );
                            }
                        }

                        prefetched = respRef;
                    }
                }
            }
            catch( LDAPException e )
            {
                try
                {
                    this.underlying.finish();
                }
                catch( Exception e2 )
                {
                }

                respDone = getResponse( req, e );
            }
        }

		private SearchResult marshall(Results underlying) throws LDAPException {
			Entry oentry = underlying.next();
			
			if (oentry != null) {
				LDAPEntry entry = oentry.getEntry();
				
				LDAPAttributeSet set = entry.getAttributeSet();
				Iterator it = set.iterator();
				Attributes attribs = new BasicAttributes();
				while (it.hasNext()) {
					LDAPAttribute ldapAttrib = (LDAPAttribute) it.next();
					BasicAttribute attrib = new BasicAttribute(ldapAttrib.getBaseName());
					String[] vals = ldapAttrib.getStringValueArray();
					for (int i=0,m=vals.length;i<m;i++) {
						attrib.add(vals[i]);
					}
					attribs.put(attrib);
					
				}
				SearchResult sRes = new SearchResult(entry.getDN(),entry,attribs);
				
				SearchResult result = sRes;
				return result;
			} else {
				return null;
			}
		}

        public boolean hasNext()
        {
            return !done;
        }

        public Object next()
        {
            Object next = prefetched;

            SearchResult result = null;

            // if we're done we got nothing to give back
            if( done )
            {
                throw new NoSuchElementException();
            }

            // if respDone has been assembled this is our last object to return
            if( respDone != null )
            {
                done = true;

                return respDone;
            }

            /*
             * If we have gotten this far then we have a valid next entry
             * or referral to return from this call in the 'next' variable.
             */
            try
            {
                /*
                 * If we have more results from the underlying cursorr then
                 * we just set the result and build the response object below.
                 */
                if( underlying.hasMore() )
                {
                    result = marshall(underlying);
                    if (result == null) {
                    	respDone = new SearchResponseDoneImpl( req.getMessageId() );

                        respDone.setLdapResult( new LdapResultImpl( respDone ) );

                        respDone.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );

                        respDone.getLdapResult().setMatchedDn( req.getBase() );

                        prefetched = null;

                        return next;
                    }
                }
                else
                {
                    try
                    {
                        underlying.finish();
                    }
                    catch( Throwable t )
                    {
                    }

                    respDone = new SearchResponseDoneImpl( req.getMessageId() );

                    respDone.setLdapResult( new LdapResultImpl( respDone ) );

                    respDone.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );

                    respDone.getLdapResult().setMatchedDn( req.getBase() );

                    prefetched = null;

                    return next;
                }
            }
            catch( LDAPException e )
            {
                try
                {
                    underlying.finish();
                }
                catch( Throwable t )
                {
                }

                prefetched = null;

                respDone = getResponse( req, e );

                return next;
            }

            /*
             * Now we have to build the prefetched object from the 'result'
             * local variable for the following call to next()
             */
            Attribute ref = result.getAttributes().get( "ref" );

            if( ref == null || ref.size() > 0 )
            {
                SearchResponseEntry respEntry = new SearchResponseEntryImpl( req.getMessageId() );

                respEntry.setAttributes( result.getAttributes() );

                respEntry.setObjectName( result.getName() );

                prefetched = respEntry;
            }
            else
            {
                SearchResponseReference respRef = new SearchResponseReferenceImpl( req.getMessageId() );

                respRef.setReferral( new ReferralImpl( respRef ) );

                for( int ii = 0; ii < ref.size(); ii ++ )
                {
                    String url;

                    try
                    {
                        url = ( String ) ref.get( ii );

                        respRef.getReferral().addLdapUrl( url );
                    }
                    catch( NamingException e )
                    {
                        try
                        {
                            underlying.finish();
                        }
                        catch( Throwable t )
                        {
                        }

                        prefetched = null;

                        respDone = getResponse( req, e );

                        return next;
                    }
                }

                prefetched = respRef;
            }

            return next;
        }

        /**
         * Unsupported so it throws an exception.
         *
         * @throws UnsupportedOperationException
         */
        public void remove()
        {
            throw new UnsupportedOperationException();
        }
    }

	public void setEnv(Insert[] globalChain, Router router) {
		this.globalChain = globalChain;
		this.router = router;
		
	}
}

