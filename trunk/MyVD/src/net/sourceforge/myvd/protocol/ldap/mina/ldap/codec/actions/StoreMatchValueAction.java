/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.actions;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.IAsn1Container;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.grammar.GrammarAction;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessageContainer;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.ExtensibleMatchFilter;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SearchRequest;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store a match value
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreMatchValueAction extends GrammarAction
{
    /** The logger */
    private static final Logger log = LoggerFactory.getLogger( StoreMatchValueAction.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = log.isDebugEnabled();

    public StoreMatchValueAction()
    {
        super( "Store match Value" );
    }

    /**
     * The initialization action
     */
    public void action( IAsn1Container container ) throws DecoderException
    {
        LdapMessageContainer ldapMessageContainer = ( LdapMessageContainer ) container;
        LdapMessage ldapMessage = ldapMessageContainer.getLdapMessage();
        SearchRequest searchRequest = ldapMessage.getSearchRequest();

        TLV tlv = ldapMessageContainer.getCurrentTLV();

        // Store the value.
        /*ExtensibleMatchFilter extensibleMatchFilter = ( ExtensibleMatchFilter ) searchRequest
            .getTerminalFilter();*/
        
        
        String value = StringTools.utf8ToString( tlv.getValue().getData() );
        
        //extensibleMatchFilter.setMatchValue( value );
        
        searchRequest.getTerminalFilter().setValue(value);

        // unstack the filters if needed
        searchRequest.unstackFilters( container );

        if ( IS_DEBUG )
        {
            log.debug( "Stored a match value : {}", value );
        }
    }
}
