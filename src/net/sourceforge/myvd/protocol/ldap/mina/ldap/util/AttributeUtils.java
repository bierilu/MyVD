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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.util;


import java.util.Arrays;




import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;


/**
 * A set of utility fuctions for working with Attributes.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 503353 $
 */
public class AttributeUtils
{
    
    /**
     * Return a string representing the attributes with tabs in front of the
     * string
     * 
     * @param tabs
     *            Spaces to be added before the string
     * @param attributes
     *            The attributes to print
     * @return A string
     */
    public static String toString( String tabs, Attribute attribute )
    {
        StringBuffer sb = new StringBuffer();

        sb.append( tabs ).append( "Attribute\n" );

        if ( attribute != null )
        {
            sb.append( tabs ).append( "    Type : '" ).append( attribute.getID() ).append( "'\n" );

            for ( int j = 0; j < attribute.size(); j++ )
            {

                try
                {
                    Object attr = attribute.get( j );

                    if ( attr != null )
                    {
                        if ( attr instanceof String )
                        {
                            sb.append( tabs ).append( "        Val[" ).append( j ).append( "] : " ).append( attr ).append(
                                " \n" );
                        }
                        else if ( attr instanceof byte[] )
                        {
                            String string = StringTools.utf8ToString( ( byte[] ) attr );
    
                            sb.append( tabs ).append( "        Val[" ).append( j ).append( "] : " );
                            sb.append( string ).append( '/' );
                            sb.append( StringTools.dumpBytes( ( byte[] ) attr ) );
                            sb.append( " \n" );
                        }
                        else
                        {
                            sb.append( tabs ).append( "        Val[" ).append( j ).append( "] : " ).append( attr ).append(
                                " \n" );
                        }
                    }
                }
                catch ( NamingException ne )
                {
                    sb.append( "Bad attribute : " ).append( ne.getMessage() );
                }
            }
        }
        
        return sb.toString();
    }

    /**
     * Return a string representing the attributes
     * 
     * @param attributes
     *            The attributes to print
     * @return A string
     */
    public static String toString( Attribute attribute )
    {
        return toString( "", attribute );
    }

    /**
     * Return a string representing the attributes with tabs in front of the
     * string
     * 
     * @param tabs
     *            Spaces to be added before the string
     * @param attributes
     *            The attributes to print
     * @return A string
     */
    public static String toString( String tabs, Attributes attributes )
    {
        StringBuffer sb = new StringBuffer();

        sb.append( tabs ).append( "Attributes\n" );

        if ( attributes != null )
        {
            NamingEnumeration attributesIterator = attributes.getAll();
    
            while ( attributesIterator.hasMoreElements() )
            {
                Attribute attribute = ( Attribute ) attributesIterator.nextElement();
    
                sb.append( tabs ).append( attribute.toString() );
            }
        }
        
        return sb.toString();
    }


    /**
     * Return a string representing the attributes
     * 
     * @param attributes
     *            The attributes to print
     * @return A string
     */
    public static String toString( Attributes attributes )
    {
        return toString( "", attributes );
    }
}
