/*
 * Copyright 2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.extensions.kerberos;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id:$
 */
public class GlobalSunJaasKerberosConfig implements BeanPostProcessor, InitializingBean {

    private boolean debug = false;
    private String krbConfLocation;

    public void afterPropertiesSet() throws Exception {
        if (debug) {
            System.setProperty("sun.security.krb5.debug", "true");
        }
        if (krbConfLocation != null) {
            System.setProperty("java.security.krb5.conf", krbConfLocation);
        }

    }
    
    
    /** 
     * Enable debug logs from the Sun Kerberos Implementation. Default is false.
     */
    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    
    /** 
     * Kerberos config file location can be specified here.
     * 
     * @param krbConfLocation
     */
    public void setKrbConfLocation(String krbConfLocation) {
        this.krbConfLocation = krbConfLocation;
    }

    
    /*
     *  The following methods are not used here. This Bean implements only BeanPostProcessor to ensure that it
     *  is created before any other bean is created, because the system properties needed to be set very early
     *  in the startup-phase, but after the BeanFactoryPostProcessing.
     */
   
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

}
