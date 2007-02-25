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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.UniversalTag;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.Value;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.util.Asn1StringUtils;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapConstants;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.AttributeUtils;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;


/**
 * A SearchResultEntry Message. Its syntax is :
 *   SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
 *       objectName      LDAPDN,
 *       attributes      PartialAttributeList }
 * 
 *   PartialAttributeList ::= SEQUENCE OF SEQUENCE {
 *       type    AttributeDescription,
 *       vals    SET OF AttributeValue }
 * 
 *   AttributeDescription ::= LDAPString
 * 
 *   AttributeValue ::= OCTET STRING
 * 
 * It contains an entry, with all its attributes, and all the attributes
 * values. If a search request is submited, all the results are sent one
 * by one, followed by a searchResultDone message.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchResultEntry extends LdapMessage
{
    // ~ Instance fields
    // ----------------------------------------------------------------------------

    /** The DN of the returned entry */
    private LdapDN objectName;
    
    /** A temporary storage for the byte[] representing the objectName */ 
    private byte[] objectNameBytes;

    
    private LDAPAttributeSet attribs = new LDAPAttributeSet();

    private LDAPAttribute attrib;
    
    
    /** The search result entry length */
    private int searchResultEntryLength;

    /** The partial attributes length */
    private int attributesLength;

    /** The list of all attributes length */
    private List<Integer> attributeLength;

    /** The list of all vals length */
    private List<Integer> valsLength;


    // ~ Constructors
    // -------------------------------------------------------------------------------

    /**
     * Creates a new SearchResultEntry object.
     */
    public SearchResultEntry()
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
        return LdapConstants.SEARCH_RESULT_ENTRY;
    }


    /**
     * Get the entry DN
     * 
     * @return Returns the objectName.
     */
    public LdapDN getObjectName()
    {
        return objectName;
    }


    /**
     * Set the entry DN
     * 
     * @param objectName The objectName to set.
     */
    public void setObjectName( LdapDN objectName )
    {
        this.objectName = objectName;
    }


    /**
     * Get the entry's attributes
     * 
     * @return Returns the partialAttributeList.
     */
    public LDAPAttributeSet getPartialAttributeList()
    {
        return this.attribs;
    }


    /**
     * Initialize the partial Attribute list.
     */
    public void setPartialAttributeList( LDAPAttributeSet partialAttributeList )
    {
        this.attribs = partialAttributeList;
    }


    /**
     * Create a new attributeValue
     * 
     * @param type The attribute's name
     */
    public void addAttributeValues( String type )
    {
        /*currentAttributeValue = new AttributeImpl( StringTools.lowerCase( type ) );

        partialAttributeList.put( currentAttributeValue );*/
        
        this.attrib = new LDAPAttribute(type);
        this.attribs.add(attrib);
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value
     */
    public void addAttributeValue( Object value )
    {
        //currentAttributeValue.add( value );
        
        
        if (value instanceof byte[]) {
        	this.attrib.addValue((byte[]) value);
        } else {
        	this.attrib.addValue((String) value); 
        }
    }


    /**
     * Compute the SearchResultEntry length
     * 
     * SearchResultEntry :
     * 
     * 0x64 L1
     *  |
     *  +--> 0x04 L2 objectName
     *  +--> 0x30 L3 (attributes)
     *        |
     *        +--> 0x30 L4-1 (partial attributes list)
     *        |     |
     *        |     +--> 0x04 L5-1 type
     *        |     +--> 0x31 L6-1 (values)
     *        |           |
     *        |           +--> 0x04 L7-1-1 value
     *        |           +--> ...
     *        |           +--> 0x04 L7-1-n value
     *        |
     *        +--> 0x30 L4-2 (partial attributes list)
     *        |     |
     *        |     +--> 0x04 L5-2 type
     *        |     +--> 0x31 L6-2 (values)
     *        |           |
     *        |           +--> 0x04 L7-2-1 value
     *        |           +--> ...
     *        |           +--> 0x04 L7-2-n value
     *        |
     *        +--> ...
     *        |
     *        +--> 0x30 L4-m (partial attributes list)
     *              |
     *              +--> 0x04 L5-m type
     *              +--> 0x31 L6-m (values)
     *                    |
     *                    +--> 0x04 L7-m-1 value
     *                    +--> ...
     *                    +--> 0x04 L7-m-n value
     * 
     */
    public int computeLength()
    {
    	objectNameBytes = StringTools.getBytesUtf8( objectName.getUpName() );
    	
        // The entry
        searchResultEntryLength = 1 + TLV.getNbBytes( objectNameBytes.length ) + objectNameBytes.length;

        // The attributes sequence
        attributesLength = 0;

        if ( ( this.attribs != null ) && ( this.attribs.size() != 0 ) )
        {
            Iterator attributes = this.attribs.iterator();
            attributeLength = new LinkedList<Integer>();
            valsLength = new LinkedList<Integer>();

            // Compute the attributes length
            while ( attributes.hasNext() )
            {
                LDAPAttribute attribute = ( LDAPAttribute ) attributes.next();

                int localAttributeLength = 0;
                int localValuesLength = 0;

                // Get the type length
                int idLength = attribute.getName().getBytes().length;
                localAttributeLength = 1 + TLV.getNbBytes( idLength ) + idLength;

                if ( attribute.size() != 0 )
                {
                    // The values
                        Enumeration values = attribute.getByteValues();

                        if ( values.hasMoreElements() )
                        {
                            localValuesLength = 0;

                            while ( values.hasMoreElements() )
                            {
                                byte[] value = (byte[]) values.nextElement();

                                
                                
                                    localValuesLength += 1 + TLV.getNbBytes( value.length )
                                        + value.length;
                                

                            }

                            localAttributeLength += 1 + TLV.getNbBytes( localValuesLength ) + localValuesLength;
                        }
                        else
                        {
                            // We have to deal with the special wase where
                            // we don't have a value.
                            // It will be encoded as an empty OCTETSTRING,
                            // so it will be two byte slong (0x04 0x00)
                            localAttributeLength += 1 + 1;
                        }

                    
                }
                else
                {
                    // We have no values. We will just have an empty SET OF :
                    // 0x31 0x00
                    localAttributeLength += 1 + 1;
                }

                // add the attribute length to the attributes length
                attributesLength += 1 + TLV.getNbBytes( localAttributeLength ) + localAttributeLength;

                attributeLength.add( localAttributeLength );
                valsLength.add( localValuesLength );
            }
        }

        searchResultEntryLength += 1 + TLV.getNbBytes( attributesLength ) + attributesLength;

        // Return the result.
        return 1 + TLV.getNbBytes( searchResultEntryLength ) + searchResultEntryLength;
    }


    /**
     * Encode the SearchResultEntry message to a PDU.
     * 
     * SearchResultEntry :
     * 
     * 0x64 LL
     *   0x04 LL objectName
     *   0x30 LL attributes
     *     0x30 LL partialAttributeList
     *       0x04 LL type
     *       0x31 LL vals
     *         0x04 LL attributeValue
     *         ... 
     *         0x04 LL attributeValue
     *     ... 
     *     0x30 LL partialAttributeList
     *       0x04 LL type
     *       0x31 LL vals
     *         0x04 LL attributeValue
     *         ... 
     *         0x04 LL attributeValue 
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
            // The SearchResultEntry Tag
            buffer.put( LdapConstants.SEARCH_RESULT_ENTRY_TAG );
            buffer.put( TLV.getBytes( searchResultEntryLength ) );

            // The objectName
            Value.encode( buffer, objectNameBytes );

            // The attributes sequence
            buffer.put( UniversalTag.SEQUENCE_TAG );
            buffer.put( TLV.getBytes( attributesLength ) );

            // The partial attribute list
            if ( ( this.attribs != null ) && ( this.attribs.size() != 0 ) )
            {
                Iterator attributes = this.attribs.iterator();
                int attributeNumber = 0;

                // Compute the attributes length
                while ( attributes.hasNext() )
                {
                    LDAPAttribute attribute = ( LDAPAttribute ) attributes.next();

                    // The partial attribute list sequence
                    buffer.put( UniversalTag.SEQUENCE_TAG );
                    int localAttributeLength = attributeLength.get( attributeNumber );
                    buffer.put( TLV.getBytes( localAttributeLength ) );

                    // The attribute type
                    Value.encode( buffer, Asn1StringUtils.asciiStringToByte( attribute.getName() ) );

                    // The values
                    buffer.put( UniversalTag.SET_TAG );
                    int localValuesLength = valsLength.get( attributeNumber );
                    buffer.put( TLV.getBytes( localValuesLength ) );

                    if ( attribute.size() != 0 )
                    {
                            Enumeration values = attribute.getByteValues();

                            if ( values.hasMoreElements() )
                            {
                                while ( values.hasMoreElements() )
                                {
                                    byte[] value = (byte[]) values.nextElement();

                                    
                                        Value.encode( buffer,  value );
                                    
                                }
                            }
                        
                    }

                    // Go to the next attribute number;
                    attributeNumber++;
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
     * Returns the Search Result Entry string
     * 
     * @return The Search Result Entry string
     */
    public String toString()
    {

        StringBuffer sb = new StringBuffer();

        sb.append( "    Search Result Entry\n" );
        sb.append( "        Object Name : '" ).append( objectName ).append( "'\n" );
        sb.append( "        Attributes\n" );

        if ( ( this.attribs == null ) || ( this.attribs.size() == 0 ) )
        {
            sb.append( "            No attributes\n" );
        }
        else
        {
            sb.append("            ").append( this.attribs.toString() ) ;
        }

        return sb.toString();
    }


    /**
     * @return Returns the currentAttributeValue.
     */
    public String getCurrentAttributeValueType()
    {
        return this.attrib.getName();
    }
}
