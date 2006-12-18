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



import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;

import org.apache.ldap.common.NotImplementedException;
import org.apache.ldap.common.message.AbandonRequest;
import org.apache.mina.protocol.ProtocolSession;
import org.apache.mina.protocol.handler.MessageHandler;



/**
 * Handler for {@link org.apache.ldap.common.message.AbandonRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 161724 $
 */
public class AbandonHandler implements MessageHandler,LdapInfo
{
    public void messageReceived( ProtocolSession session, Object request )
    {
        AbandonRequest req = ( AbandonRequest ) request;
        int abandonedId = req.getAbandoned();

        if ( abandonedId < 0 )
        {
            return;
        }
        
        throw new NotImplementedException( "don't know how to do this just yet" );
    }

	public void setEnv(Insert[] globalChain, Router router) {
		// TODO Auto-generated method stub
		
	}
}
