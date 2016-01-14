package org.wso2.carbon.jwt.helper.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.jwt.helper.JWTHelperDataHolder;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="jwt.helper.dscomponent" immediate=true
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */


public class JWTHelperDSComponent {

    private static Log log = LogFactory.getLog(JWTHelperDSComponent.class);

    protected void activate(ComponentContext ctxt) {

        log.info("JWTHelper bundle activated successfully..");
    }

    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("JWTHelper bundle is deactivated ");
        }
    }

    protected void setRealmService(RealmService realmService) {

        JWTHelperDataHolder.getInstance().setRealmService(realmService);

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
    }

    protected void unsetRealmService(RealmService realmService) {

        JWTHelperDataHolder.getInstance().setRealmService(null);

        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Realm Service");
        }
    }

    public static RealmService getRealmService() {
        return JWTHelperDataHolder.getInstance().getRealmService();
    }

}
