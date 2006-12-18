package net.sourceforge.myvd.protocol.ldap;

import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;

public interface LdapInfo {
	public void setEnv(Insert[] globalChain,Router router);
}
