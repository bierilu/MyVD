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
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;





import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.DeleteRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.LdapResult;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.ExceptionUtils;
import org.apache.mina.common.IoSession;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;



import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;


/**
 * A single reply handler for {@link org.apache.ldap.common.message.DeleteRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 231083 $
 */
public class DeleteHandler extends LDAPOperation
{
    private static final Logger LOG = LoggerFactory.getLogger( DeleteHandler.class );
	

    public void messageReceived( IoSession session, Object request,HashMap userRequest,HashMap userSession,DistinguishedName bindDN,Password pass )
    {
        DeleteRequest req = ( DeleteRequest ) request;
        LdapResult result = req.getResultResponse().getLdapResult();

        
        
        
        
        try
        {
        	userSession = (HashMap) session.getAttribute("MYVD_SESSION");
            
            
            DeleteInterceptorChain chain = new DeleteInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,router);
            chain.nextDelete(new DistinguishedName(req.getName().toString()),new LDAPConstraints());
            
        }
        catch( LDAPException e )
        {
            String msg = "failed to delete entry " + req.getName();

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
					result.setMatchedDn( new LdapDN(e.getMatchedDN()) );
				} catch (InvalidNameException e1) {
					LOG.error("Error",e1);
				}
            }

            session.write( req.getResultResponse() );
            return;
        }catch (Throwable t) {
        	
            String msg = "failed to delete entry " + req.getName() + "; " + t.toString();

            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( t );
            }

            ResultCodeEnum code;

            
                code = ResultCodeEnum.OPERATIONS_ERROR;
            

            result.setResultCode( code );
            result.setErrorMessage( msg );
            

            session.write( req.getResultResponse() );
            return;
        
    }

        result.setResultCode( ResultCodeEnum.SUCCESS );
        result.setMatchedDn( req.getName() );
        session.write( req.getResultResponse() );
    }


	
}
