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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.modify;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.UniversalTag;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.Value;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapConstants;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPModification;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;


/**
 * A ModifyRequest Message. 
 * 
 * Its syntax is : 
 * 
 * ModifyRequest ::= [APPLICATION 6] SEQUENCE { 
 *     object LDAPDN, 
 *     modification SEQUENCE OF SEQUENCE { 
 *         operation ENUMERATED { 
 *             add (0), 
 *             delete (1), 
 *             replace (2) 
 *         }, 
 *         modification AttributeTypeAndValues 
 *     } 
 * } 
 * 
 * AttributeTypeAndValues ::= SEQUENCE {
 *     type AttributeDescription, 
 *     vals SET OF AttributeValue 
 * } 
 * 
 * AttributeValue ::= OCTET STRING
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ModifyRequest extends LdapMessage
{
    // ~ Static fields/initializers
    // -----------------------------------------------------------------

    /** The logger */
    private static final Logger log = LoggerFactory.getLogger( ModifyRequest.class );

    // ~ Instance fields
    // ----------------------------------------------------------------------------

    /** The DN to be modified. */
    private LdapDN object;

    /** A local storage for the operation */
    private int currentOperation;

    /** The modify request length */
    private int modifyRequestLength;

    /** The modifications length */
    private int modificationsLength;

    /** The modification sequence length */
    private List<Integer> modificationSequenceLength;

    /** The list of all modification length */
    private List<Integer> modificationLength;

    /** The list of all vals length */
    private List<Integer> valuesLength;
    
    private ArrayList<LDAPModification> mods;
    
    private LDAPModification mod;
    
    private LDAPAttribute attrib;


    // ~ Constructors
    // -------------------------------------------------------------------------------

    /**
     * Creates a new ModifyRequest object.
     */
    public ModifyRequest()
    {
        super();
    }


    // ~ Methods
    // ------------------------------------------------------------------------------------

    /**
     * Get the message type
     * 
     * @return Returns the type.
     */
    public int getMessageType()
    {
        return LdapConstants.MODIFY_REQUEST;
    }


    /**
     * Initialize the ArrayList for modifications.
     */
    public void initModifications()
    {

        this.mods = new ArrayList<LDAPModification>();
    }


    


    /**
     * Add a new modification to the list
     * 
     * @param operation The type of operation (add, delete or replace)
     */
    public void addModification( int operation )
    {
        currentOperation = operation;

       
        
        
    }


    /**
     * Add a new attributeTypeAndValue
     * 
     * @param type The attribute's name
     */
    public void addAttributeTypeAndValues( String type )
    {
        
        
        this.attrib = new LDAPAttribute(type);
        this.mod = new LDAPModification(this.currentOperation,attrib);
        this.mods.add(mod);
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     */
    public void addAttributeValue( Object value )
    {
        
        
        if (value instanceof String) {
        	this.attrib.addValue((String) value);
        } else {
        	this.attrib.addValue((byte[]) value);
        }
    }


    /**
     * Return the current attribute's type
     */
    public String getCurrentAttributeType()
    {
        return "";
    }


    /**
     * Get the modification's DN
     * 
     * @return Returns the object.
     */
    public LdapDN getObject()
    {
        return object;
    }


    /**
     * Set the modification DN.
     * 
     * @param object The DN to set.
     */
    public void setObject( LdapDN object )
    {
        this.object = object;
    }


    /**
     * Get the current operation
     * 
     * @return Returns the currentOperation.
     */
    public int getCurrentOperation()
    {
        return currentOperation;
    }


    /**
     * Store the current operation
     * 
     * @param currentOperation The currentOperation to set.
     */
    public void setCurrentOperation( int currentOperation )
    {
        this.currentOperation = currentOperation;
    }


    /**
     * Compute the ModifyRequest length 
     * 
     * ModifyRequest :
     * 
     * 0x66 L1
     *  |
     *  +--> 0x04 L2 object
     *  +--> 0x30 L3 modifications
     *        |
     *        +--> 0x30 L4-1 modification sequence
     *        |     |
     *        |     +--> 0x0A 0x01 (0..2) operation
     *        |     +--> 0x30 L5-1 modification
     *        |           |
     *        |           +--> 0x04 L6-1 type
     *        |           +--> 0x31 L7-1 vals
     *        |                 |
     *        |                 +--> 0x04 L8-1-1 attributeValue
     *        |                 +--> 0x04 L8-1-2 attributeValue
     *        |                 +--> ...
     *        |                 +--> 0x04 L8-1-i attributeValue
     *        |                 +--> ...
     *        |                 +--> 0x04 L8-1-n attributeValue
     *        |
     *        +--> 0x30 L4-2 modification sequence
     *        .     |
     *        .     +--> 0x0A 0x01 (0..2) operation
     *        .     +--> 0x30 L5-2 modification
     *                    |
     *                    +--> 0x04 L6-2 type
     *                    +--> 0x31 L7-2 vals
     *                          |
     *                          +--> 0x04 L8-2-1 attributeValue
     *                          +--> 0x04 L8-2-2 attributeValue
     *                          +--> ...
     *                          +--> 0x04 L8-2-i attributeValue
     *                          +--> ...
     *                          +--> 0x04 L8-2-n attributeValue
     */
    public int computeLength()
    {
        // Initialized with object
        modifyRequestLength = 1 + TLV.getNbBytes( LdapDN.getNbBytes( object ) ) + LdapDN.getNbBytes( object );

        // Modifications
        modificationsLength = 0;

        if ( ( this.mods != null ) && ( this.mods.size() != 0 ) )
        {
            Iterator<LDAPModification> modificationsIterator = this.mods.iterator();
            modificationSequenceLength = new LinkedList<Integer>();
            modificationLength = new LinkedList<Integer>();
            valuesLength = new LinkedList<Integer>();

            while ( modificationsIterator.hasNext() )
            {
                // Modification sequence length initialized with the operation
                int localModificationSequenceLength = 1 + 1 + 1;
                int localValuesLength = 0;

                LDAPModification modification = modificationsIterator.next();

                // Modification length initialized with the type
                int typeLength = modification.getAttribute().getName().length();
                int localModificationLength = 1 + TLV.getNbBytes( typeLength ) + typeLength;

                
                    Enumeration values = modification.getAttribute().getByteValues();

                    // Get all the values
                    if ( values.hasMoreElements() )
                    {
                        while ( values.hasMoreElements() )
                        {
                            byte[] value = (byte[]) values.nextElement();

                            
                                localValuesLength += 1 + TLV.getNbBytes( (  value ).length )
                                    + (  value ).length;
                            
                        }
                    }

                    localModificationLength += 1 + TLV.getNbBytes( localValuesLength ) + localValuesLength;
                
                

                // Compute the modificationSequenceLength
                localModificationSequenceLength += 1 + TLV.getNbBytes( localModificationLength )
                    + localModificationLength;

                // Add the tag and the length
                modificationsLength += 1 + TLV.getNbBytes( localModificationSequenceLength )
                    + localModificationSequenceLength;

                // Store the arrays of values
                valuesLength.add( localValuesLength );
                modificationLength.add( localModificationLength );
                modificationSequenceLength.add( localModificationSequenceLength );
            }

            // Add the modifications length to the modificationRequestLength
            modifyRequestLength += 1 + TLV.getNbBytes( modificationsLength ) + modificationsLength;
        }

        return 1 + TLV.getNbBytes( modifyRequestLength ) + modifyRequestLength;
    }


    /**
     * Encode the ModifyRequest message to a PDU. 
     * 
     * ModifyRequest : 
     * 0x66 LL
     *   0x04 LL object
     *   0x30 LL modifiations
     *     0x30 LL modification sequence
     *       0x0A 0x01 operation
     *       0x30 LL modification
     *         0x04 LL type
     *         0x31 LL vals
     *           0x04 LL attributeValue
     *           ... 
     *           0x04 LL attributeValue
     *     ... 
     *     0x30 LL modification sequence
     *       0x0A 0x01 operation
     *       0x30 LL modification
     *         0x04 LL type
     *         0x31 LL vals
     *           0x04 LL attributeValue
     *           ... 
     *           0x04 LL attributeValue
     * 
     * 
     * @param buffer The buffer where to put the PDU
     * @return The PDU.
     */
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( "Cannot put a PDU in a null buffer !" );
        }

        try
        {
            // The AddRequest Tag
            buffer.put( LdapConstants.MODIFY_REQUEST_TAG );
            buffer.put( TLV.getBytes( modifyRequestLength ) );

            // The entry
            Value.encode( buffer, LdapDN.getBytes( object ) );

            // The modifications sequence
            buffer.put( UniversalTag.SEQUENCE_TAG );
            buffer.put( TLV.getBytes( modificationsLength ) );

            // The modifications list
            if ( ( this.mods != null ) && ( this.mods.size() != 0 ) )
            {
                Iterator<LDAPModification> modificationIterator = this.mods.iterator();
                int modificationNumber = 0;

                // Compute the modifications length
                while ( modificationIterator.hasNext() )
                {
                    LDAPModification modification = modificationIterator.next();

                    // The modification sequence
                    buffer.put( UniversalTag.SEQUENCE_TAG );
                    int localModificationSequenceLength = modificationSequenceLength
                        .get( modificationNumber );
                    buffer.put( TLV.getBytes( localModificationSequenceLength ) );

                    // The operation. The value has to be changed, it's not
                    // the same value in DirContext and in RFC 2251.
                    buffer.put( UniversalTag.ENUMERATED_TAG );
                    buffer.put( ( byte ) 1 );

                    switch ( modification.getOp() )
                    {

                        case LDAPModification.ADD: // add
                            buffer.put( ( byte ) LdapConstants.OPERATION_ADD );
                            break;

                        case LDAPModification.DELETE: // delete
                            buffer.put( ( byte ) LdapConstants.OPERATION_DELETE );
                            break;

                        case LDAPModification.REPLACE: // replace
                            buffer.put( ( byte ) LdapConstants.OPERATION_REPLACE );
                            break;
                    }

                    // The modification
                    buffer.put( UniversalTag.SEQUENCE_TAG );
                    int localModificationLength = modificationLength.get( modificationNumber );
                    buffer.put( TLV.getBytes( localModificationLength ) );

                    // The modification type
                    Value.encode( buffer, modification.getAttribute().getName() );

                    // The values
                    buffer.put( UniversalTag.SET_TAG );
                    int localValuesLength = valuesLength.get( modificationNumber );
                    buffer.put( TLV.getBytes( localValuesLength ) );

                    
                        Enumeration values = modification.getAttribute().getByteValues();

                        if ( values.hasMoreElements() )
                        {
                            while ( values.hasMoreElements() )
                            {
                                byte[] value = (byte[]) values.nextElement();

                                
                                    Value.encode( buffer, value );
                                
                            }
                        }

                    
                    

                    // Go to the next modification number;
                    modificationNumber++;
                }
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( "The PDU buffer size is too small !" );
        }

        return buffer;
    }


    /**
     * Get a String representation of a ModifyRequest
     * 
     * @return A ModifyRequest String
     */
    public String toString()
    {
        StringBuffer sb = new StringBuffer();

        sb.append( "    Modify Request\n" );
        sb.append( "        Object : '" ).append( object ).append( "'\n" );

        if ( this.mods != null )
        {
            int i = 0;
            
            for ( LDAPModification modification:this.mods )
            {
                sb.append( "            Modification[" ).append( i ).append( "]\n" );
                sb.append( "                Operation : " );

                if ( modification != null )
                {
                    switch ( modification.getOp() )
                    {
    
                        case DirContext.ADD_ATTRIBUTE:
                            sb.append( " add\n" );
                            break;
    
                        case DirContext.REPLACE_ATTRIBUTE:
                            sb.append( " replace\n" );
                            break;
    
                        case DirContext.REMOVE_ATTRIBUTE:
                            sb.append( " delete\n" );
                            break;
                    }

                    sb.append( "                Modification\n" );
    
                    LDAPAttribute attribute = modification.getAttribute();
    
                    if ( attribute != null )
                    {
                        
                            sb.append( "                    Type : '" ).append( attribute.getName() ).append( "'\n" );
                            sb.append( "                    Vals\n" );
        
                            for ( int j = 0; j < attribute.size(); j++ )
                            {
        
                                Object attributeValue = attribute.getByteValueArray()[ j ];
                                sb.append( "                        Val[" ).append( j ).append( "] : '" );
        
                                if ( attributeValue != null )
                                {
                                    if ( attributeValue instanceof String )
                                    {
                                        sb.append( attributeValue ).append( "' \n" );
                                    }
                                    else
                                    {
                                        sb.append( StringTools.utf8ToString( ( byte[] ) attributeValue ) ).append( "' \n" );
                                    }
                                }
                                else
                                {
                                    sb.append( "<null>'\n" );
                                }
                            }
                        
                        
                    }
                }
                else
                {
                    sb.append( " unknown modification operation\n" );
                }

            }
        }

        return sb.toString();
    }
    
    public ArrayList<LDAPModification> getMods() {
    	return this.mods;
    }
}
