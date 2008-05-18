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

package net.sourceforge.myvd.protocol.ldap;

import java.util.Iterator;
import java.util.NoSuchElementException;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.exception.LdapException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.LdapResult;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ReferralImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchResponseDone;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchResponseDoneImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchResponseEntry;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchResponseEntryImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchResponseReference;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.SearchResponseReferenceImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.ExceptionUtils;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPException;

public class SearchResponseIterator implements Iterator
{
    private final SearchRequest req;

    private final Results underlying;

    private SearchResponseDone respDone;

    private boolean done = false;

    private Object prefetched;
    
    private static final Logger LOG = LoggerFactory.getLogger( SearchResponseIterator.class );

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
                
            	//SearchResult result = marshall(underlying);
            	Entry oentry = underlying.next();

            	
            	
                /*
                 * Now we have to build the prefetched object from the 'result'
                 * local variable for the following call to next()
                 */
                LDAPAttribute ref = oentry.getEntry().getAttribute("ref");

                if( ref == null || ref.size() > 0 )
                {
                    SearchResponseEntry respEntry;

                    respEntry = new SearchResponseEntryImpl( req.getMessageId() );

                    respEntry.setLDAPAttributeSet( oentry.getEntry().getAttributeSet() );

                    try {
						respEntry.setObjectName( new LdapDN(oentry.getEntry().getDN()) );
					} catch (InvalidNameException e) {
						LOG.error("Error",e);
					}

                    prefetched = respEntry;
                }
                else
                {
                    SearchResponseReference respRef;

                    respRef = new SearchResponseReferenceImpl( req.getMessageId() );

                    respRef.setReferral( new ReferralImpl(  ) );

                    String[] vals = ref.getStringValueArray();
                    
                    for( int ii = 0; ii < vals.length; ii ++ )
                    {
                        String url;

                        
                            url = vals[ ii ];

                            respRef.getReferral().addLdapUrl( url );
                        
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

	

    public boolean hasNext()
    {
        return !done;
    }

    public Object next()
    {
        Object next = prefetched;


        Entry oentry = null;
        
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
                oentry = underlying.next();
                if (oentry == null) {
                	

                	respDone = ( SearchResponseDone ) req.getResultResponse();
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

                respDone = ( SearchResponseDone ) req.getResultResponse();
                respDone.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
                respDone.getLdapResult().setMatchedDn( req.getBase() );
                respDone.getLdapResult().setErrorMessage("");
                respDone.getLdapResult().setReferral(new ReferralImpl(  ));
                /*respDone = new SearchResponseDoneImpl( req.getMessageId() );

                respDone.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );

                

                respDone.getLdapResult().setMatchedDn( req.getBase() );*/

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
        LDAPAttribute ref = oentry.getEntry().getAttribute("ref");

        if( ref == null || ref.size() > 0 )
        {
            SearchResponseEntry respEntry = new SearchResponseEntryImpl( req.getMessageId() );

            respEntry.setLDAPAttributeSet( oentry.getEntry().getAttributeSet() );

            try {
				respEntry.setObjectName( new LdapDN(oentry.getEntry().getDN()) );
			} catch (InvalidNameException e) {
				LOG.error("Error",e);
			}

            prefetched = respEntry;
        }
        else
        {
            SearchResponseReference respRef = new SearchResponseReferenceImpl( req.getMessageId() );

            respRef.setReferral( new ReferralImpl(  ) );
            String[] vals = ref.getStringValueArray();
            for( int ii = 0; ii < vals.length; ii ++ )
            {
                	String url;
                
                    url = vals[ii];

                    respRef.getReferral().addLdapUrl( url );
                
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

        LdapResult result = req.getResultResponse().getLdapResult();
        result.setResultCode( rc );
        result.setErrorMessage( msg );
        
        

        if( e.getResolvedName() != null )
        {
            try {
				resp.getLdapResult().setMatchedDn( new LdapDN(e.getResolvedName().toString()) );
			} catch (InvalidNameException e1) {
				LOG.error("Error",e1);
			}
        }
        else
        {
            try {
				resp.getLdapResult().setMatchedDn( new LdapDN("") );
			} catch (InvalidNameException e1) {
				LOG.error("Error",e1);
			}
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

        
        rc = ResultCodeEnum.getResultCode(e.getResultCode());
        

        LdapResult result = req.getResultResponse().getLdapResult();
        result.setResultCode( rc );
        result.setErrorMessage( msg );
        
        

        if( e.getMatchedDN() != null )
        {
            try {
				resp.getLdapResult().setMatchedDn( new LdapDN(e.getMatchedDN()) );
			} catch (InvalidNameException e1) {
				LOG.error("Error",e1);
			}
        }
        else
        {
            try {
				resp.getLdapResult().setMatchedDn( new LdapDN("") );
			} catch (InvalidNameException e1) {
				LOG.error("Error",e1);
			}
        }

        return resp;
    }
}