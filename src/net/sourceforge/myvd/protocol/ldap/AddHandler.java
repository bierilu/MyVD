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

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapContext;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.exception.LdapException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.AddRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.AddResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.AddResponseImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.LdapResult;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.ExceptionUtils;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.Password;




import org.apache.mina.common.IoSession;

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
public class AddHandler extends LDAPOperation
{
    private static final Logger LOG = LoggerFactory.getLogger( AddHandler.class );

    
    
    public void messageReceived( IoSession session, Object request,HashMap userRequest,HashMap userSession,DistinguishedName bindDN,Password pass ) 
    {
        AddRequest req = ( AddRequest ) request;
        LdapResult result = req.getResultResponse().getLdapResult();
        

        
        try
        {
        	
        	/*LDAPAttributeSet set = new LDAPAttributeSet();
			
			NamingEnumeration nenum = req.getAttributes().getAll();
			while (nenum.hasMore()) {
				Attribute attrib = (Attribute) nenum.next();
				/*if (this.toIgnore.contains(attrib.getID().toLowerCase())) {
					continue;
				}
				LDAPAttribute ldapAttrib = new LDAPAttribute(attrib.getID());
				NamingEnumeration vals = attrib.getAll();
				while (vals.hasMore()) {
					ldapAttrib.addValue((String) vals.next());
				}
				
				set.add(ldapAttrib);
	   		}*/
        	
            AddInterceptorChain chain = new AddInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
            chain.nextAdd(new Entry(new LDAPEntry(req.getEntry().toNormName(),req.getAttribSet())),new LDAPConstraints());
        }
        catch( LDAPException e )
        {
            String msg = "failed to add entry " + req.getEntry() + "; " + e.getLDAPErrorMessage();

            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( e );
            }

            ResultCodeEnum code;

            
                code = ResultCodeEnum.getResultCode(e.getResultCode());
            

            
            result.setResultCode( code );
            result.setErrorMessage( msg );
            
            
            if( e.getMatchedDN() != null )
            {
            	try {
					result.setMatchedDn(
					        new LdapDN(e.getMatchedDN()) );
				} catch (InvalidNameException e1) {
					LOG.error("Error",e1);
				}
            }

            session.write( req.getResultResponse() );
            return;
        
        
        } catch (Throwable t) {
        	
                String msg = "failed to add entry " + req.getEntry() + "; " + t.toString();

              
                    msg += ":\n" + ExceptionUtils.getStackTrace( t );
                
        

                ResultCodeEnum code;

                
                    code = ResultCodeEnum.OPERATIONS_ERROR;
                

                result.setResultCode( code );
                result.setErrorMessage( msg );
                

                session.write( req.getResultResponse() );
                return;
            
        }

        result.setResultCode( ResultCodeEnum.SUCCESS );
        
        session.write( req.getResultResponse() );
    }

	
	
}

