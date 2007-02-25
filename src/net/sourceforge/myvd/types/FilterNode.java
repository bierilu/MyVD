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
package net.sourceforge.myvd.types;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.Filter;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;

public class FilterNode implements Cloneable {
	FilterType type;
	String name;
	String value;
	FilterNode not;
	ArrayList<FilterNode> children;
	FilterNode parent;
	
	public FilterNode(FilterType type,String name,String value) {
		this.type = type;
		this.name = name;
		this.value = value;
		this.not = null;
		this.children = null;
	}
	
	public FilterNode(FilterType type,ArrayList<FilterNode> children) {
		this.type = type;
		this.children = children;
		this.name = null;
		this.value = null;
		this.not = null;
	}
	
	public FilterNode(FilterNode not) {
		this.type = FilterType.NOT;
		this.not = not;
		this.children = null;
		this.name = null;
		this.value = null;
	}

	public ArrayList<FilterNode> getChildren() {
		return children;
	}

	public void setChildren(ArrayList<FilterNode> children) {
		this.children = children;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public FilterNode getNot() {
		return not;
	}

	public void setNot(FilterNode not) {
		this.not = not;
	}

	public FilterType getType() {
		return type;
	}

	public void setType(FilterType type) {
		this.type = type;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public @Override Object clone() throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (this.type) {
			case PRESENCE :
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
			case SUBSTR:
				newNode = new FilterNode(this.type,this.name,this.value);
				return newNode;
			
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = this.children.iterator();
				while (it.hasNext()) {
					newChildren.add((FilterNode) it.next().clone());
				}
				
				
				newNode = new FilterNode(this.type,newChildren);
				return newNode;
				
			case NOT:
				return new FilterNode((FilterNode) this.not.clone());
		}
		
		return null;
	}
	
	public void readFromNode(FilterNode node) throws LDAPException {
		this.type = node.type;
		this.name = node.name;
		this.value = node.value;
		
		if (node.not != null) {
			try {
				this.not = (FilterNode) node.not.clone();
			} catch (CloneNotSupportedException e) {
				throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,"");
			}
		}
		
		
		if (node.children != null) {
			this.children = new ArrayList<FilterNode>();
			Iterator<FilterNode> it = node.children.iterator();
			while (it.hasNext()) {
				try {
					node.children.add((FilterNode) it.next().clone());
				} catch (CloneNotSupportedException e) {
					throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,"");
				}
			}
		}
	}
	
	public String toString() {
		StringBuffer buf = new StringBuffer();
		this.toString(buf);
		return buf.toString();
	}
	
	protected void toString(StringBuffer buf) {
		Iterator<FilterNode> it;
		
		switch (this.type) {
			case PRESENCE : buf.append('(').append(this.name).append("=*)"); break;
			case SUBSTR:
			case EQUALS : buf.append('(').append(this.name).append('=').append(this.value).append(')'); break;
			case GREATER_THEN : buf.append('(').append(this.name).append(">=").append(this.value).append(')'); break;
			case LESS_THEN : buf.append('(').append(this.name).append("<=").append(this.value).append(')'); break;
			case AND : buf.append("(&");
					   it = this.children.iterator();
					   while (it.hasNext()) {
						   it.next().toString(buf);
					   }
					   buf.append(')');
					   break;
					   
			case OR :  buf.append("(|");
					   it = this.children.iterator();
					   while (it.hasNext()) {
						   it.next().toString(buf);
					   }
					   buf.append(')');
					   break;
			
			case NOT : buf.append("(!");
					   this.not.toString(buf);
					   buf.append(')');
					   break;
					   
		}
	}

	public void addNode(FilterNode node) {
		if (this.type == FilterType.AND || this.type == FilterType.OR) {
			this.children.add(node);
		} else {
			this.not = node;
		}
		
	}
	
	
	
	public boolean checkEntry(LDAPEntry entry) {
		Iterator<FilterNode> it;
		LDAPAttributeSet attribs;
		LDAPAttribute attrib;
		Enumeration enumer;
		
		switch (this.type) {
			case PRESENCE : return entry.getAttributeSet().getAttribute(this.name) != null;
			case SUBSTR: return false; //TODO Add substring support
			case EQUALS :  attribs = entry.getAttributeSet();
						   attrib = attribs.getAttribute(this.name);
						   
						   if (attrib == null) {
							   return false;
						   }
						   
						   enumer = attrib.getStringValues();
						   while (enumer.hasMoreElements()) {
							   if (enumer.nextElement().toString().equalsIgnoreCase(this.value)) {
								   return true;
							   }
						   }
						   
						   return false;
			case GREATER_THEN : attribs = entry.getAttributeSet();
								   attrib = attribs.getAttribute(this.name);
								   
								   if (attrib == null) {
									   return false;
								   }
								   
								   enumer = attrib.getStringValues();
								   while (enumer.hasMoreElements()) {
									   if (enumer.nextElement().toString().compareToIgnoreCase(this.value) > 0) {
										   return true;
									   }
								   }
								   
								   return false;
			case LESS_THEN : attribs = entry.getAttributeSet();
							   attrib = attribs.getAttribute(this.name);
							   
							   if (attrib == null) {
								   return false;
							   }
							   
							   enumer = attrib.getStringValues();
							   while (enumer.hasMoreElements()) {
								   if (enumer.nextElement().toString().compareToIgnoreCase(this.value) < 0) {
									   return true;
								   }
							   }
							   
							   return false;
			case AND : 
					   it = this.children.iterator();
					   while (it.hasNext()) {
						   if (! it.next().checkEntry(entry)) {
							   return false;
						   }
					   }
					   return true;
					   
			case OR :  it = this.children.iterator();
					   while (it.hasNext()) {
						   if (it.next().checkEntry(entry)) {
							   return true;
						   }
					   }
					   return false;
					   
			
			case NOT : return ! this.not.checkEntry(entry);
					   
		}
		
		return false;
	}
	
	public int getWeight() {
		Iterator<FilterNode> it;
		LDAPAttributeSet attribs;
		LDAPAttribute attrib;
		Enumeration enumer;
		int w = 0;
		int sum = 0;
		int curw = 0;
		
		switch (this.type) {
			case PRESENCE : return 1;
			case SUBSTR: return 2;
			case EQUALS :  return 3;
			case GREATER_THEN : return 2;
			case LESS_THEN : return 2;
			case AND : 
					   it = this.children.iterator();
					   while (it.hasNext()) {
						   sum += it.next().getWeight();
					   }
					   return sum;
					   
			case OR :  it = this.children.iterator();
					   while (it.hasNext()) {
						   curw = it.next().getWeight();
						   if (curw == 0 || curw > w) {
							   w = curw;
						   }
					   }
					   return w;
					   
			
			case NOT : return 4 - this.not.getWeight();
					   
		}
		
		return 0;
	}

	public FilterNode getParent() {
		return parent;
	}

	public void setParent(FilterNode parent) {
		this.parent = parent;
	}
	
	protected int computeLength() {
		return 0;
		/*
		int length;
		switch (this.type) {
		case AND :
		case OR:
			length = this.computeFilterSetLength();
			break;
		case NOT:
			length = this.not.computeLength();
			break;
		case GREATER_THEN:
		case LESS_THEN:
		case EQUALS:
			length = this.computeAVALength();
			break;
		case PRESENCE:
			length = this.computePresenceLength();
			break;
		case EXT:
			length = 0; //this isn't going to fly
			break;
		case SUBSTR:
			
		
			
			
		}*/
	}
	
	/**
     * Compute the ConnectorFilter length Length(ConnectorFilter) =
     * sum(filterSet.computeLength())
     */
    private int computeFilterSetLength()
    {
        int connectorFilterLength = 0;

        if ( ( this.children != null ) && ( children.size() != 0 ) )
        {
            Iterator<FilterNode> filterIterator = this.children.iterator();

            while ( filterIterator.hasNext() )
            {
                FilterNode filterNode = filterIterator.next();

                connectorFilterLength += filterNode.computeLength();
            }
        }

        return connectorFilterLength;
    }
	
    /**
     * Compute the AttributeValueFilter length
     * 
     * AttributeValueFilter :
     * 
     * 0xA(3, 5, 6, 8) L1
     *  |
     *  +--> 0x04 L2 attributeDesc
     *  +--> 0x04 L3 assertionValue
     *  
     * 
     * L2 = Length(attributeDesc)
     * L3 = Length(assertionValue)
     * L1 = 1 + Length(L2) + L2 
     *      + 1 + Length(L3) + L3
     * 
     * Length(AttributeValueFilter) = Length(0xA?) + Length(L1)
     *                                + 1 + Length(L2) + L2 
     *                                + 1 + Length(L3) + L3 
     */
    private int computeAVALength()
    {
        int avaLength = 0;
        int attributeDescLength = this.name.length();

        avaLength = 1 + TLV.getNbBytes( attributeDescLength ) + attributeDescLength;

        int assertionValueLength = StringTools.getBytesUtf8( this.value ).length;
        
        avaLength += 1 + TLV.getNbBytes( assertionValueLength ) + assertionValueLength;

        return 1 + TLV.getNbBytes( avaLength ) + avaLength;
    }
	
    /**
     * Compute the PresentFilter length 
     * PresentFilter : 
     * 0x87 L1 present
     * 
     * Length(PresentFilter) = Length(0x87) + Length(super.computeLength()) +
     *      super.computeLength()
     */
    private int computePresenceLength()
    {
        byte[] attributeDescriptionBytes = StringTools.getBytesUtf8( name );
        return 1 + TLV.getNbBytes( attributeDescriptionBytes.length ) + attributeDescriptionBytes.length;
    }
    
    /**
     * Compute the SubstringFilter length 
     * 
     * SubstringFilter : 
     * 0xA4 L1 
     *   | 
     *   +--> 0x04 L2 type 
     *   +--> 0x30 L3 
     *          | 
     *         [+--> 0x80 L4 initial] 
     *         [+--> 0x81 L5-1 any] 
     *         [+--> 0x81 L5-2 any] 
     *         [+--> ... 
     *         [+--> 0x81 L5-i any] 
     *         [+--> ... 
     *         [+--> 0x81 L5-n any] 
     *         [+--> 0x82 L6 final]
     */
    private int computeSubstrLength()
    {
        // The type
        /*int typeLength = StringTools.getBytesUtf8( name ).length;
        
        int substringsFilterLength = 1 + TLV.getNbBytes( typeLength ) + typeLength;
        int substringsFilterSequenceLength = 0;

        String initialSubstrings = this.value.substring(0,value.indexOf('*'));
        
        if ( initialSubstrings.length() != 0 )
        {
            int initialLength = StringTools.getBytesUtf8( initialSubstrings ).length; 
            substringsFilterSequenceLength += 1 + TLV.getNbBytes( initialLength )
                + initialLength;
        }

        if ( anySubstrings != null )
        {
            Iterator anyIterator = anySubstrings.iterator();

            while ( anyIterator.hasNext() )
            {
                String any = ( String ) anyIterator.next();
                int anyLength = StringTools.getBytesUtf8( any ).length; 
                substringsFilterSequenceLength += 1 + TLV.getNbBytes( anyLength ) + anyLength;
            }
        }

        if ( finalSubstrings != null )
        {
            int finalLength = StringTools.getBytesUtf8( finalSubstrings ).length; 
            substringsFilterSequenceLength += 1 + TLV.getNbBytes( finalLength )
                + finalLength;
        }

        substringsFilterLength += 1 + TLV.getNbBytes( substringsFilterSequenceLength )
            + substringsFilterSequenceLength;
    	
    	

        return 1 + TLV.getNbBytes( substringsFilterLength ) + substringsFilterLength;*/
    	return 0;
    }
}
