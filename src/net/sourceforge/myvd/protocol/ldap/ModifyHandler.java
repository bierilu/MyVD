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

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapContext;

import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;

import org.apache.ldap.common.exception.LdapException;
import org.apache.ldap.common.message.LdapResultImpl;
import org.apache.ldap.common.message.ModifyRequest;
import org.apache.ldap.common.message.ModifyResponse;
import org.apache.ldap.common.message.ModifyResponseImpl;
import org.apache.ldap.common.message.ResultCodeEnum;
import org.apache.ldap.common.util.ExceptionUtils;
import org.apache.mina.protocol.ProtocolSession;
import org.apache.mina.protocol.handler.MessageHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;


/**
 * A single reply handler for {@link org.apache.ldap.common.message.ModifyRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 231083 $
 */
public class ModifyHandler implements MessageHandler,LdapInfo
{
    private static final Logger LOG = LoggerFactory.getLogger( ModifyHandler.class );
    private static final ModificationItem[] EMPTY = new ModificationItem[0];
	private Insert[] globalChain;
	private Router router;


    public void messageReceived( ProtocolSession session, Object request )
    {
        ModifyRequest req = ( ModifyRequest ) request;
        ModifyResponse resp = new ModifyResponseImpl( req.getMessageId() );
        resp.setLdapResult( new LdapResultImpl( resp ) );

        HashMap userSession;
        try
        {
            
        	ModificationItem[] attribs = (ModificationItem[]) req.getModificationItems().toArray( EMPTY );
            
            ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>(attribs.length);
			
			for (int i=0,m=attribs.length;i<m;i++) {
				mods.add(this.createChange(attribs[i].getAttribute(),attribs[i].getModificationOp()));
			}
			
			userSession = (HashMap) session.getAttribute("MYVD_SESSION");
            DistinguishedName bindDN = (DistinguishedName) session.getAttribute("MYVD_BINDDN");
            Password pass = (Password) session.getAttribute("MYVD_BINDPASS");
            
            if (bindDN == null) {
            	bindDN = new DistinguishedName("");
            	pass = new Password();
            
            }
            
            ModifyInterceptorChain chain = new ModifyInterceptorChain(bindDN,pass,0,this.globalChain,userSession,new HashMap(),this.router);
            chain.nextModify(new DistinguishedName(req.getName()),mods,new LDAPConstraints());
            
            
        }
        catch ( LDAPException e )
        {
            String msg = "failed to modify entry " + req.getName();
	    
            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( e );
            }

            ResultCodeEnum code;
            code = ResultCodeEnum.getResultCodeEnum(e.getResultCode());
            

            resp.getLdapResult().setResultCode( code );
            resp.getLdapResult().setErrorMessage( msg );

            if ( e.getMatchedDN() != null )
            {
                resp.getLdapResult().setMatchedDn( e.getMatchedDN() );
            }

            session.write( resp );
            return;
        }
        catch ( NamingException e )
        {
            String msg = "failed to modify entry " + req.getName();
	    
            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( e );
            }

            ResultCodeEnum code;
            if ( e instanceof LdapException )
            {
                code = ( ( LdapException ) e ).getResultCode() ;
            }
            else
            {
                code = ResultCodeEnum.getBestEstimate( e, req.getType() );
            }

            resp.getLdapResult().setResultCode( code );
            resp.getLdapResult().setErrorMessage( msg );

            if ( e.getResolvedName() != null )
            {
                resp.getLdapResult().setMatchedDn( e.getResolvedName().toString() );
            }

            session.write( resp );
            return;
        }catch (Throwable t) {
        	
            String msg = "failed to add entry " + req.getName() + "; " + t.toString();

            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( t );
            }

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
        return;
    }
    
    private LDAPModification createChange(Attribute attrib,int type) throws NamingException {
		
    	if (type == 1) {
    		type = 0;
    	} else if (type == 3) {
    		type = 1;
    	}
    	
		LDAPAttribute ldapAttrib = new LDAPAttribute(attrib.getID());
		NamingEnumeration vals = attrib.getAll();
		while (vals.hasMore()) {
			ldapAttrib.addValue((String) vals.next());
		}
		
		
		LDAPModification newMod = new LDAPModification(type,ldapAttrib);
		System.err.println("Modification : " + type + ";" + newMod);
		return newMod;
	}


	public void setEnv(Insert[] globalChain, Router router) {
		this.globalChain = globalChain;
		this.router = router;
		
	}
}

