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

import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.AbandonRequestImpl;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;

import org.apache.mina.common.IoSession;
import org.apache.mina.handler.demux.MessageHandler;





/**
 * Handler for {@link org.apache.ldap.common.message.AbandonRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 161724 $
 */
public class AbandonHandler extends LDAPOperation
{
    public void messageReceived( IoSession session, Object request,HashMap userRequest,HashMap userSession,DistinguishedName bindDN,Password pass )
    {
        AbandonRequestImpl req = ( AbandonRequestImpl ) request;
        int abandonedId = req.getAbandoned();

        if ( abandonedId < 0 )
        {
            return;
        }
        
        throw new net.sourceforge.myvd.protocol.ldap.mina.ldap.NotImplementedException( "don't know how to do this just yet" );
    }

	
}
