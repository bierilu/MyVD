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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.message;


import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPModification;


/**
 * Lockable ModifyRequest implementation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 494173 $
 */
public class ModifyRequestImpl extends AbstractAbandonableRequest implements ModifyRequest
{
    static final long serialVersionUID = -505803669028990304L;

    /** The logger */
    private static final transient Logger log = LoggerFactory.getLogger( ModifyRequestImpl.class );

    /** Dn of the entry to modify or PDU's <b>object</b> field */
    private LdapDN name;

    /** Sequence of modifications or PDU's <b>modification</b> seqence field */
    private ArrayList mods = new ArrayList();

    private ModifyResponse response;
    
    private ArrayList<LDAPModification> ldapMods;


    // ------------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------------

    /**
     * Creates a Lockable ModifyRequest implementing object used to modify the
     * attributes of an entry.
     * 
     * @param id
     *            the sequential message identifier
     */
    public ModifyRequestImpl(final int id)
    {
        super( id, TYPE );
    }


    // ------------------------------------------------------------------------
    // ModifyRequest Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Gets an immutable Collection of modification items representing the
     * atomic changes to perform on the candidate entry to modify.
     * 
     * @return an immutatble Collection of ModificationItem instances.
     * @see <{javax.naming.directory.ModificationItem}>
     */
    public Collection getModificationItems()
    {
        return Collections.unmodifiableCollection( mods );
    }


    /**
     * Gets the distinguished name of the entry to be modified by this request.
     * This property represents the PDU's <b>object</b> field.
     * 
     * @return the DN of the modified entry.
     */
    public LdapDN getName()
    {
        return name;
    }


    /**
     * Sets the distinguished name of the entry to be modified by this request.
     * This property represents the PDU's <b>object</b> field.
     * 
     * @param name
     *            the DN of the modified entry.
     */
    public void setName( LdapDN name )
    {
        this.name = name;
    }


   

    // ------------------------------------------------------------------------
    // SingleReplyRequest Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Gets the protocol response message type for this request which produces
     * at least one response.
     * 
     * @return the message type of the response.
     */
    public MessageTypeEnum getResponseType()
    {
        return RESP_TYPE;
    }


    /**
     * The result containing response for this request.
     * 
     * @return the result containing response for this request
     */
    public ResultResponse getResultResponse()
    {
        if ( response == null )
        {
            response = new ModifyResponseImpl( getMessageId() );
        }

        return response;
    }


    /**
     * Checks to see if ModifyRequest stub equals another by factoring in checks
     * for the name and modification items of the request.
     * 
     * @param obj
     *            the object to compare this ModifyRequest to
     * @return true if obj equals this ModifyRequest, false otherwise
     */
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }

        if ( !super.equals( obj ) )
        {
            return false;
        }

        ModifyRequest req = ( ModifyRequest ) obj;

        if ( name != null && req.getName() == null )
        {
            return false;
        }

        if ( name == null && req.getName() != null )
        {
            return false;
        }

        if ( name != null && req.getName() != null )
        {
            if ( !name.equals( req.getName() ) )
            {
                return false;
            }
        }

        if ( req.getModificationItems().size() != mods.size() )
        {
            return false;
        }

        /*Iterator list = req.getModificationItems().iterator();

        for ( int ii = 0; ii < mods.size(); ii++ )
        {
            ModificationItemImpl item = ( ModificationItemImpl ) list.next();

            if ( !equals( ( ModificationItemImpl ) mods.get( ii ), item ) )
            {
                return false;
            }
        }*/

        return true;
    }


    





	public void setLdapMods(ArrayList<LDAPModification> ldapMods) {
		this.ldapMods = ldapMods;
	}


	public ArrayList<LDAPModification> getMods() {
		return this.ldapMods;
	}
}
