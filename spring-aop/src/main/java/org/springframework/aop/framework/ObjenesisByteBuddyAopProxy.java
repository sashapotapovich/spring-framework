package org.springframework.aop.framework;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.objenesis.SpringObjenesis;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Constructor;

public class ObjenesisByteBuddyAopProxy extends ByteBuddyAopProxy {

    private static final Log logger = LogFactory.getLog(ObjenesisCglibAopProxy.class);

    private static final SpringObjenesis objenesis = new SpringObjenesis();

    /**
     * Create a new ObjenesisByteBuddyAopProxy for the given AOP configuration.
     *
     * @param config the AOP configuration as AdvisedSupport object
     */
    public ObjenesisByteBuddyAopProxy(AdvisedSupport config) {
        super(config);
    }

    @Override
    protected Object createProxyInstance(Class<?> proxyClass, boolean useCache) throws Exception {
        Object proxyInstance = null;

        if (objenesis.isWorthTrying()) {
            try {
                proxyInstance = objenesis.newInstance(proxyClass, useCache);
            } catch (Throwable ex) {
                logger.debug("Unable to instantiate proxy using Objenesis, " +
                        "falling back to regular proxy construction", ex);
            }
        }

        if (proxyInstance == null) {
            // Regular instantiation via default constructor...
            try {
                Constructor<?> ctor = (this.constructorArgs != null ?
                        proxyClass.getDeclaredConstructor(this.constructorArgTypes) :
                        proxyClass.getDeclaredConstructor());
                ReflectionUtils.makeAccessible(ctor);
                proxyInstance = (this.constructorArgs != null ?
                        ctor.newInstance(this.constructorArgs) : ctor.newInstance());
            } catch (Throwable ex) {
                throw new AopConfigException("Unable to instantiate proxy using Objenesis, " +
                        "and regular proxy instantiation via default constructor fails as well", ex);
            }
        }

        return proxyInstance;
    }

}

