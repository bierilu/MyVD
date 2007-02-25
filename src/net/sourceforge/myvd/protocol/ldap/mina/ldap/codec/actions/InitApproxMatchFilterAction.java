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
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapConstants;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessageContainer;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.AttributeValueAssertionFilter;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.Filter;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.SearchRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialize the Approx Match filter
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitApproxMatchFilterAction extends GrammarAction
{
    /** The logger */
    private static final Logger log = LoggerFactory.getLogger( InitApproxMatchFilterAction.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = log.isDebugEnabled();

    public InitApproxMatchFilterAction()
    {
        super( "Init Approx Match filter Value" );
    }

    public void action( IAsn1Container container ) throws DecoderException
    {
        LdapMessageContainer ldapMessageContainer = ( LdapMessageContainer ) container;
        LdapMessage ldapMessage = ldapMessageContainer.getLdapMessage();
        SearchRequest searchRequest = ldapMessage.getSearchRequest();

        // We can allocate the Attribute Value Assertion
        /*Filter filter = new AttributeValueAssertionFilter( 
            ldapMessageContainer.getMessageId(),
            LdapConstants.APPROX_MATCH_FILTER );*/

        FilterNode node = new FilterNode(FilterType.EQUALS,"","");
        
        searchRequest.addCurrentFilter( node );
        
        // Store the filter structure that still has to be
        // fullfiled
        searchRequest.setTerminalFilter( node );
        
        if ( IS_DEBUG )
        {
            log.debug( "Initialize Approx Match filter" );
        }
    }
}
