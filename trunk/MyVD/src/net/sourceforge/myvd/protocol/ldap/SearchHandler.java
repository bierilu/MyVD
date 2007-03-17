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

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;


import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.types.SessionVariables;






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
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.ArrayUtils;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.ExceptionUtils;
import org.apache.mina.common.IoSession;
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
public class SearchHandler extends LDAPOperation 
{
    private static final Logger LOG = LoggerFactory.getLogger( SearchHandler.class );
    private static final String DEREFALIASES_KEY = "java.naming.ldap.derefAliases";

   

    
    
    public void messageReceived( IoSession session, Object request,HashMap userRequest,HashMap userSession,DistinguishedName bindDN,Password pass )
    {
        
        SearchRequest req = ( SearchRequest ) request;
        

        // check the attributes to see if a referral's ref attribute is included
        Attribute[] ids = null;
        Collection retAttrs = new HashSet();
        /*retAttrs.addAll( req.getAttributes() );

        if( retAttrs.size() > 0 && !retAttrs.contains( "ref" ) )
        {
            retAttrs.add( "ref" );
            ids = ( Attribute[] ) retAttrs.toArray( ArrayUtils.EMPTY_STRING_ARRAY );
        }
        else if( retAttrs.size() > 0 )
        {
            ids = ( Attribute[] ) retAttrs.toArray( ArrayUtils.EMPTY_STRING_ARRAY );
        }*/

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
            

        	
            
            Results res = new Results(this.globalChain);
            StringBuffer buff = new StringBuffer();
            
            //req.getFilter().printToBuffer(buff);
            
            //String stringFilter = buff.toString();
			//System.out.println("Filter b: \"" + stringFilter + "\"");
			//stringFilter = stringFilter.replaceAll("[|] ","|");
			//stringFilter = stringFilter.replaceAll("[)] ",")");
			//stringFilter = stringFilter.replaceAll("[&] ","&");
			//stringFilter = stringFilter.replaceAll("[!] ","!");
			//System.out.println("Filter a: \"" + stringFilter + "\"");
            
			Filter filter = req.getFilter();//   new Filter(stringFilter.trim()); 
            
			
			
            Iterator it;
            ArrayList<net.sourceforge.myvd.types.Attribute> reqAttribs = req.getAttributes();
            
            DistinguishedName base = new DistinguishedName(req.getBase() == null ? "" : req.getBase().toString()); 
            
            SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
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
                
                /*SearchResponseDone resp = new SearchResponseDoneImpl( req.getMessageId() );
                resp.setLdapResult( new LdapResultImpl( resp ) );
                resp.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
                resp.getLdapResult().setMatchedDn( req.getBase() );
                it = Collections.singleton( resp ).iterator();*/
            	
            	LdapResult result = req.getResultResponse().getLdapResult();
                result.setResultCode( ResultCodeEnum.SUCCESS );
                result.setErrorMessage( "" );
            	
                

                session.write(req.getResultResponse());
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

            
            rc = ResultCodeEnum.getResultCode(e.getResultCode());
            
            if (rc == null) {
            	rc = ResultCodeEnum.OPERATIONS_ERROR;
            }
            
            
            
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
					result.setMatchedDn( new LdapDN("") );
				} catch (InvalidNameException e1) {
					LOG.error("Error",e1);
				}
            }

            session.write(req.getResultResponse());
            
        } catch (Throwable t) {
        	t.printStackTrace();
            String msg = "failed to search "  + t.toString();
            SearchResponseDone resp = new SearchResponseDoneImpl( req.getMessageId() );
            ResultCodeEnum rc = null;
            
                msg += ":\n" + ExceptionUtils.getStackTrace( t );
            

            ResultCodeEnum code;

            
                code = ResultCodeEnum.OPERATIONS_ERROR;
            

            resp.getLdapResult().setResultCode( code );
            resp.getLdapResult().setErrorMessage( msg );
            

            session.write( resp );
            return;
        
    }
    }


    
    
    

    






	
}

