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



import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.spi.InitialContextFactory;

import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.SessionVariables;


/*
 * I would like to eventually see these newly introduced dependencies
 * within the core (apacheds-core dep added to LDAP pp).  This way we
 * can still have the potential to use the PP as a pure LDAP proxy
 * server (however this might be an unlikely occurrance).  We can figure
 * this out later there are bigger issues to solve right now.
 *
 * The changes are the two lines below:
 */






import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.BindRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.BindResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.BindResponseImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.Control;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.LdapResult;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.LdapResultImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.ExceptionUtils;
import org.apache.mina.common.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;



/**
 * A single reply handler for {@link org.apache.ldap.common.message.BindRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 231083 $
 */
public class BindHandler extends LDAPOperation
{
    private static final Logger LOG = LoggerFactory.getLogger( BindHandler.class );
    private static final Control[] EMPTY = new Control[0];
    
   


    public void messageReceived( IoSession session, Object request,HashMap userRequest,HashMap userSession,DistinguishedName bindDN,Password pass )
    {

        BindRequest req = ( BindRequest ) request;
        BindResponse resp = new BindResponseImpl( req.getMessageId() );
        LdapResult result = req.getResultResponse().getLdapResult();
        

       
        // if the bind request is not simple then we freak: no strong auth yet
        if ( ! req.isSimple() )
        {
            result.setResultCode( ResultCodeEnum.AUTH_METHOD_NOT_SUPPORTED );
            result.setErrorMessage( "Only simple binds currently supported" );
            session.write( resp );
            return;
        }

       
        boolean emptyCredentials = req.getCredentials() == null || req.getCredentials().length == 0;
        boolean emptyDn = req.getName() == null || req.getName().size() == 0;

        /*if ( emptyCredentials && emptyDn && ! allowAnonymousBinds )
        {
            result.setResultCode( ResultCodeEnum.INSUFFICIENTACCESSRIGHTS );
            String msg = "Bind failure: Anonymous binds have been disabled!";
            result.setErrorMessage( msg );
            session.write( resp );
            return;
        }*/

        // clone the environment first then add the required security settings

        String dn = req.getName().toString();

        //System.err.println("Bind credentials : " + dn);
        
        byte[] creds = req.getCredentials();

        
        Control[] connCtls = ( Control[] ) req.getControls().values().toArray( EMPTY );

        
        
        try
        {
            
            
            DistinguishedName newBindDN = new DistinguishedName(dn);
            Password newPass = new Password(creds);
            
            BindInterceptorChain chain = new BindInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,router);
            chain.nextBind(newBindDN,newPass,new LDAPConstraints());
            
            session.setAttribute("MYVD_BINDDN",newBindDN);
            session.setAttribute("MYVD_BINDPASS",newPass);
            
        }
        catch( LDAPException e )
        {
           
        	//bind failed, reset the session username and pass
        	userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
        	session.setAttribute("MYVD_BINDDN",new DistinguishedName(""));
            session.setAttribute("MYVD_BINDPASS",new Password());
        	
            result.setResultCode( ResultCodeEnum.getResultCode(e.getResultCode())  );
            

            String msg = "Bind failed ;" + e.getMessage();

            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( e );
                msg += "\n\nBindRequest = \n" + req.toString();
            }


            result.setErrorMessage( msg );
            session.write( req.getResultResponse() );
            return;
        }catch (Throwable t) {
        	
            String msg = "failed to add entry " + req.getName() + "; " + t.toString();

            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( t );
            }

            ResultCodeEnum code;

            
                code = ResultCodeEnum.OPERATIONS_ERROR;
            

            resp.getLdapResult().setResultCode( code );
            resp.getLdapResult().setErrorMessage( msg );
            

            session.write( req.getResultResponse() );
            return;
        
    }

        
        result.setResultCode( ResultCodeEnum.SUCCESS );
        result.setMatchedDn( req.getName() );
        session.write( req.getResultResponse() );
    }


	
}

