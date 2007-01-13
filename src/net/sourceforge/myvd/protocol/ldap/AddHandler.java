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


import java.util.HashMap;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapContext;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.Password;

import org.apache.ldap.common.exception.LdapException;
import org.apache.ldap.common.message.AddRequest;
import org.apache.ldap.common.message.AddResponse;
import org.apache.ldap.common.message.AddResponseImpl;
import org.apache.ldap.common.message.LdapResultImpl;
import org.apache.ldap.common.message.ResultCodeEnum;
import org.apache.ldap.common.util.ExceptionUtils;
import org.apache.mina.protocol.ProtocolSession;
import org.apache.mina.protocol.handler.MessageHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;


/**
 * A single reply handler for {@link org.apache.ldap.common.message.AddRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 231083 $
 */
public class AddHandler implements MessageHandler,LdapInfo
{
    private static final Logger LOG = LoggerFactory.getLogger( AddHandler.class );

    Insert[] globalChain;
    Router router;
    
    public void messageReceived( ProtocolSession session, Object request ) 
    {
        AddRequest req = ( AddRequest ) request;
        AddResponse resp = new AddResponseImpl( req.getMessageId() );
        resp.setLdapResult( new LdapResultImpl( resp ) );

        HashMap userSession = null;
        
        userSession = (HashMap) session.getAttribute("MYVD_SESSION");
        DistinguishedName bindDN = (DistinguishedName) session.getAttribute("MYVD_BINDDN");
        Password pass = (Password) session.getAttribute("MYVD_BINDPASS");
        
        try
        {
        	
        	LDAPAttributeSet set = new LDAPAttributeSet();
			
			NamingEnumeration nenum = req.getEntry().getAll();
			while (nenum.hasMore()) {
				Attribute attrib = (Attribute) nenum.next();
				/*if (this.toIgnore.contains(attrib.getID().toLowerCase())) {
					continue;
				}*/
				LDAPAttribute ldapAttrib = new LDAPAttribute(attrib.getID());
				NamingEnumeration vals = attrib.getAll();
				while (vals.hasMore()) {
					ldapAttrib.addValue((String) vals.next());
				}
				
				set.add(ldapAttrib);
	   		}
        	
            AddInterceptorChain chain = new AddInterceptorChain(bindDN,pass,0,this.globalChain,userSession,new HashMap(),this.router);
            chain.nextAdd(new Entry(new LDAPEntry(req.getName(),set)),new LDAPConstraints());
        }
        catch( LDAPException e )
        {
            String msg = "failed to add entry " + req.getName() + "; " + e.getLDAPErrorMessage();

            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( e );
            }

            ResultCodeEnum code;

            
                code = ResultCodeEnum.getResultCodeEnum(e.getResultCode());
            

            resp.getLdapResult().setResultCode( code );
            resp.getLdapResult().setErrorMessage( msg );
            if( e.getMatchedDN() != null )
            {
                resp.getLdapResult().setMatchedDn(
                        e.getMatchedDN() );
            }

            session.write( resp );
            return;
        }
        catch( NamingException e )
        {
            String msg = "failed to add entry " + req.getName();

            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( e );
            }

            ResultCodeEnum code;

            if( e instanceof LdapException )
            {
                code = ( ( LdapException ) e ).getResultCode();
            }
            else
            {
                code = ResultCodeEnum.getBestEstimate( e, req.getType() );
            }

            resp.getLdapResult().setResultCode( code );
            resp.getLdapResult().setErrorMessage( msg );
            if( e.getResolvedName() != null )
            {
                resp.getLdapResult().setMatchedDn(
                        e.getResolvedName().toString() );
            }

            session.write( resp );
            return;
        } catch (Throwable t) {
        	
                String msg = "failed to add entry " + req.getName() + "; " + t.toString();

              
                    msg += ":\n" + ExceptionUtils.getStackTrace( t );
                
        

                ResultCodeEnum code;

                
                    code = ResultCodeEnum.OPERATIONSERROR;
                

                resp.getLdapResult().setResultCode( code );
                resp.getLdapResult().setErrorMessage( msg );
                

                session.write( resp );
                return;
            
        }

        resp.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
        resp.getLdapResult().setMatchedDn( req.getName() );
        session.write( resp );
    }

	public void setEnv(Insert[] globalChain, Router router) {
		this.globalChain = globalChain;
		this.router = router;
		
	}
}

