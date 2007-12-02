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
package net.sourceforge.myvd.core;

import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;

public class NameSpace {
	DistinguishedName base;
	int weight;
	String label;
	
	Insert[] chain;
	Router router;
	
	boolean isGlobal;
	
	public NameSpace(String label,DistinguishedName base,int weight,Insert[] chain,boolean isGlobal) {
		this.base = base;
		this.weight = weight;
		this.label = label;
		this.chain = chain;
		this.isGlobal = isGlobal;
	}
	
	public DistinguishedName getBase() {
		return this.base;
	}

	public int getWeight() {
		return this.weight;
	}
	
	public String getLabel() {
		return this.label;
	}
	
	public String toString() {
		return this.label + ";" + this.base.getDN().toString() + ";" + this.weight;
	}

	public Insert[] getChain() {
		return this.chain;
	}

	public Router getRouter() {
		return router;
	}

	public void setRouter(Router router) {
		this.router = router;
	}
	
	public int getPositionInChain(Insert insert) {
		for (int i=0;i<this.chain.length;i++) {
			if (this.chain[i] == insert) {
				return i;
			}
		}
		
		return -1;
	}

	public boolean isGlobal() {
		return isGlobal;
	}
}
