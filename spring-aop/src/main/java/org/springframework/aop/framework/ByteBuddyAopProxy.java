package org.springframework.aop.framework;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.NamingStrategy;
import net.bytebuddy.TypeCache;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.implementation.*;
import net.bytebuddy.implementation.bind.annotation.*;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.AopInvocationException;
import org.springframework.aop.RawTargetAccess;
import org.springframework.aop.TargetSource;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.SmartClassLoader;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.UndeclaredThrowableException;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.function.Function;

public class ByteBuddyAopProxy implements AopProxy, Serializable {

    private static final String ADVISED = "advised";

    /**
     * Logger available to subclasses; static to optimize serialization
     */
    protected static final Log logger = LogFactory.getLog(ByteBuddyAopProxy.class);

    /**
     * A cache that is used for avoiding repeated proxy creation.
     */
    private static final TypeCache<Object> cache = new TypeCache.WithInlineExpunction<>(TypeCache.Sort.SOFT);

    /**
     * Keeps track of the Classes that we have validated for final methods
     */
    private static final Map<Class<?>, Boolean> validatedClasses = new WeakHashMap<>();

    /**
     * The configuration used to configure this proxy
     */
    protected final AdvisedSupport advised;

    protected Object[] constructorArgs;

    protected Class<?>[] constructorArgTypes;

    /**
     * Create a new ByteBuddyAopProxy for the given AOP configuration.
     *
     * @param config the AOP configuration as AdvisedSupport object
     * @throws AopConfigException if the config is invalid. We try to throw an informative
     *                            exception in this case, rather than let a mysterious failure happen later.
     */
    public ByteBuddyAopProxy(AdvisedSupport config) throws AopConfigException {
        Assert.notNull(config, "AdvisedSupport must not be null");
        if (config.getAdvisors().length == 0 && config.getTargetSource() == AdvisedSupport.EMPTY_TARGET_SOURCE) {
            throw new AopConfigException("No advisors and no TargetSource specified");
        }
        this.advised = config;
    }

    /**
     * Set constructor arguments to use for creating the proxy.
     *
     * @param constructorArgs     the constructor argument values
     * @param constructorArgTypes the constructor argument types
     */
    public void setConstructorArguments(Object[] constructorArgs, Class<?>[] constructorArgTypes) {
        if (constructorArgs == null || constructorArgTypes == null) {
            throw new IllegalArgumentException("Both 'constructorArgs' and 'constructorArgTypes' need to be specified");
        }
        if (constructorArgs.length != constructorArgTypes.length) {
            throw new IllegalArgumentException("Number of 'constructorArgs' (" + constructorArgs.length +
                    ") must match number of 'constructorArgTypes' (" + constructorArgTypes.length + ")");
        }
        this.constructorArgs = constructorArgs;
        this.constructorArgTypes = constructorArgTypes;
    }

    @Override
    public Object getProxy() {
        return getProxy(null);
    }

    @Override
    public Object getProxy(ClassLoader classLoader) {
        if (logger.isDebugEnabled()) {
            logger.debug("Creating Byte Buddy proxy: target source is " + this.advised.getTargetSource());
        }

        try {
            Class<?> rootClass = this.advised.getTargetClass();
            Assert.state(rootClass != null, "Target class must be available for creating a Byte Buddy proxy");

            Class<?> proxySuperClass = rootClass;
            if (AopUtils.isByteBuddyProxyClass(rootClass)) {
                proxySuperClass = rootClass.getSuperclass();
                Class<?>[] additionalInterfaces = rootClass.getInterfaces();
                for (Class<?> additionalInterface : additionalInterfaces) {
                    if (additionalInterface != ByteBuddyProxy.class) {
                        this.advised.addInterface(additionalInterface);
                    }
                }
            }

            validateClassIfNecessary(proxySuperClass, classLoader);

            boolean useCache = !(classLoader instanceof SmartClassLoader) || ((SmartClassLoader) classLoader).isClassReloadable(proxySuperClass);

            boolean exposeProxy = this.advised.isExposeProxy();
            boolean isStatic = this.advised.getTargetSource().isStatic();
            boolean isFrozen = this.advised.isFrozen();
            Class<?>[] proxyInterfaces = AopProxyUtils.completeProxiedInterfaces(this.advised);

            Class<?> proxyType = null;

            Object cacheKey = null;

            ClassLoader targetClassLoader;
            if (classLoader == null) {
                targetClassLoader = proxySuperClass.getClassLoader();
                if (targetClassLoader == null) {
                    targetClassLoader = getClass().getClassLoader();
                }
            } else {
                targetClassLoader = classLoader;
            }

            if (useCache) {
                cacheKey = generateCacheKey(proxySuperClass, proxyInterfaces, exposeProxy, isStatic, isFrozen);
                proxyType = cache.find(targetClassLoader, cacheKey);
            }

            if (proxyType == null) {

                synchronized (cache) {

                    if (useCache) {
                        proxyType = cache.find(targetClassLoader, cacheKey);
                    }

                    if (proxyType == null) {
                        ByteBuddy byteBuddy = createByteBuddy();
                        byteBuddy = byteBuddy.ignore(ElementMatchers.none());
                        byteBuddy = byteBuddy.with(new NamingStrategy.SuffixingRandom("SpringProxy"));

                        DynamicType.Builder<?> builder = byteBuddy.subclass(proxySuperClass);
                        builder = builder.implement(proxyInterfaces);

                        builder = configure(builder, rootClass, exposeProxy, isStatic, isFrozen);

                        builder = builder.defineField(ADVISED, AdvisedSupport.class, Visibility.PRIVATE);
                        builder = builder.implement(ByteBuddyProxy.class)
                                .method(ElementMatchers.named("$$_spring_setAdvised").or(ElementMatchers.named("$$_spring_getAdvised")))
                                .intercept(FieldAccessor.ofField(ADVISED));

                        proxyType = builder.make().load(targetClassLoader).getLoaded();

                        if (useCache) {
                            proxyType = cache.insert(targetClassLoader, cacheKey, proxyType);
                        }
                    }
                }

            }

            Object proxy = createProxyInstance(proxyType, useCache);
            ((ByteBuddyProxy) proxy).$$_spring_setAdvised(this.advised);

            return proxy;
        } catch (IllegalStateException ex) {
            throw new AopConfigException("Could not generate Byte Buddy subclass of class [" +
                    this.advised.getTargetClass() + "]: " +
                    "Common causes of this problem include using a final class or a non-visible class",
                    ex);
        } catch (Exception ex) {
            // TargetSource.getTarget() failed
            throw new AopConfigException("Unexpected AOP exception", ex);
        }
    }

    protected Object createProxyInstance(Class<?> proxyClass, boolean useCache) throws Exception {
        return this.constructorArgs != null ?
                proxyClass.getDeclaredConstructor(this.constructorArgTypes).newInstance(this.constructorArgs) :
                proxyClass.getDeclaredConstructor().newInstance();
    }

    /**
     * Creates a {@link ByteBuddy} configuration. Subclasses may wish to override this to return a custom
     * configuration.
     */
    protected ByteBuddy createByteBuddy() {
        return new ByteBuddy().with(TypeValidation.DISABLED);
    }

    /**
     * Checks to see whether the supplied {@code Class} has already been validated and
     * validates it if not.
     */
    private void validateClassIfNecessary(Class<?> proxySuperClass, ClassLoader proxyClassLoader) {
        if (logger.isInfoEnabled()) {
            synchronized (validatedClasses) {
                if (!validatedClasses.containsKey(proxySuperClass)) {
                    doValidateClass(proxySuperClass, proxyClassLoader);
                    validatedClasses.put(proxySuperClass, Boolean.TRUE);
                }
            }
        }
    }

    /**
     * Checks for final methods on the given {@code Class}, as well as package-visible
     * methods across ClassLoaders, and writes warnings to the log for each one found.
     */
    private void doValidateClass(Class<?> proxySuperClass, ClassLoader proxyClassLoader) {
        if (Object.class != proxySuperClass) {
            Method[] methods = proxySuperClass.getDeclaredMethods();
            for (Method method : methods) {
                int mod = method.getModifiers();
                if (!Modifier.isStatic(mod)) {
                    if (Modifier.isFinal(mod)) {
                        logger.info("Unable to proxy method [" + method + "] because it is final: " +
                                "All calls to this method via a proxy will NOT be routed to the target instance.");
                    } else if (!Modifier.isPublic(mod) && !Modifier.isProtected(mod) && !Modifier.isPrivate(mod) &&
                            proxyClassLoader != null && proxySuperClass.getClassLoader() != proxyClassLoader) {
                        logger.info("Unable to proxy method [" + method + "] because it is package-visible " +
                                "across different ClassLoaders: All calls to this method via a proxy will " +
                                "NOT be routed to the target instance.");
                    }
                }
            }
            doValidateClass(proxySuperClass.getSuperclass(), proxyClassLoader);
        }
    }

    /**
     * Process a return value. Wraps a return of {@code this} if necessary to be the
     * {@code proxy} and also verifies that {@code null} is not returned as a primitive.
     */
    private static Object processReturnType(Object proxy, Object target, Method method, Object retVal) {
        // Massage return value if necessary
        if (retVal != null && retVal == target &&
                !RawTargetAccess.class.isAssignableFrom(method.getDeclaringClass())) {
            // Special case: it returned "this". Note that we can't help
            // if the target sets a reference to itself in another returned object.
            retVal = proxy;
        }
        Class<?> returnType = method.getReturnType();
        if (retVal == null && returnType != Void.TYPE && returnType.isPrimitive()) {
            throw new AopInvocationException(
                    "Null return value from advice does not match primitive return type for: " + method);
        }
        return retVal;
    }

    /**
     * Allows to configure a class in a custom manner. A custom configuration must yield the same proxy for equal
     * input parameters. Alternatively, {@link ByteBuddyAopProxy#generateCacheKey(Class, Class[], boolean, boolean, boolean)}
     * can be overridden where any custom configuration must yield a key with equal constraints.
     *
     * @param builder     The builder that should be used for creating the proxy.
     * @param rootClass   The root class that is being proxied.
     * @param exposeProxy If this proxy is exposed.
     * @param isStatic    If this proxy is static.
     * @param isFrozen    If this proxy is frozen.
     * @return A fully configured builder.
     * @throws Exception If an error occurs during the configuration.
     */
    protected DynamicType.Builder<?> configure(DynamicType.Builder<?> builder,
                                               Class<?> rootClass,
                                               boolean exposeProxy,
                                               boolean isStatic,
                                               boolean isFrozen) throws Exception {

        Class<?> targetClass = this.advised.getTargetClass();

        MethodDelegation.WithCustomProperties invokeConfiguration = MethodDelegation.withDefaultConfiguration()
                .withBinders(Pipe.Binder.install(Function.class));
        MethodDelegation invokeTarget;
        if (exposeProxy) {
            invokeTarget = invokeConfiguration.to(isStatic ?
                    StaticUnadvisedExposedInterceptor.class :
                    DynamicUnadvisedExposedInterceptor.class);
        } else {
            invokeTarget = invokeConfiguration.to(isStatic ?
                    StaticUnadvisedInterceptor.class :
                    DynamicUnadvisedInterceptor.class);
        }

        MethodDelegation aopProxy = MethodDelegation.to(DynamicAdvisedInterceptor.class);

        Implementation adviceDispatched = MethodCall.invokeSelf().onField(ADVISED).withAllArguments();

        Implementation dispatchTarget = isStatic ?
                MethodDelegation.withDefaultConfiguration().withBinders(Pipe.Binder.install(Function.class)).to(ForwardingInterceptor.class) :
                SuperMethodCall.INSTANCE;

        builder = builder.ignoreAlso((ElementMatcher<MethodDescription>) target -> {
            if (ElementMatchers.isFinalizer().matches(target)) {
                logger.debug("Found finalize() method - using NO_OVERRIDE");
                return true;
            }
            return false;
        });

        builder = builder.method(target -> {
            if (logger.isDebugEnabled()) {
                logger.debug("Method " + target +
                        "has return type that is assignable from the target type (may return this) - " +
                        "using INVOKE_TARGET");
            }
            return true;
        }).intercept(invokeTarget);

        builder = builder.method(target -> {
            TypeDescription returnType = target.getReturnType().asErasure();
            if (returnType.isPrimitive() || !returnType.isAssignableFrom(targetClass)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Method " + target +
                            " has return type that ensures this cannot be returned- using DISPATCH_TARGET");
                }
                return true;
            }
            return false;
        }).intercept(dispatchTarget);

        builder = builder.method(target -> {
            TypeDescription returnType = target.getReturnType().asErasure();
            if (returnType.represents(targetClass)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Method " + target +
                            "has return type same as target type (may return this) - using INVOKE_TARGET");
                }
                return true;
            }
            return false;
        }).intercept(invokeTarget);

        builder = builder.method(target -> {
            // See if the return type of the method is outside the class hierarchy
            // of the target type. If so we know it never needs to have return type
            // massage and can use a dispatcher.
            // If the proxy is being exposed, then must use the interceptor the
            // correct one is already configured. If the target is not static, then
            // cannot use a dispatcher because the target cannot be released.
            return exposeProxy || !isStatic;
        }).intercept(invokeTarget);

        builder = builder.method(target -> {
            Method method = ((MethodDescription.ForLoadedMethod) target.asDefined()).getLoadedMethod();
            if (!this.advised.getInterceptorsAndDynamicInterceptionAdvice(method, targetClass).isEmpty() || !isFrozen) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Unable to apply any optimisations to advised method: " + target);
                }
                return true;
            } else {
                return false;
            }
        }).intercept(aopProxy);

        if (isStatic && isFrozen) {
            Method[] methods = rootClass.getMethods();

            // TODO: small memory optimisation here (can skip creation for methods with no advice)
            for (Method method : methods) {
                List<Object> chain = this.advised.getInterceptorsAndDynamicInterceptionAdvice(method, rootClass);
                Implementation fixedChainStaticTargetInterceptor = MethodDelegation.to(new FixedChainStaticTargetInterceptor(chain));

                builder = builder.method(target -> {
                    if (target.asDefined().represents(method)) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Method has advice and optimisations are enabled: " + target);
                        }
                        return true;
                    }
                    return false;
                }).intercept(fixedChainStaticTargetInterceptor);
            }
        }

        builder = builder.method(target -> {
            // If exposing the proxy, then AOP_PROXY must be used.
            if (exposeProxy) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Must expose proxy on advised method: " + target);
                }
                return true;
            }
            return false;
        }).intercept(aopProxy);

        builder = builder.method(target -> {
            if (ElementMatchers.isHashCode().matches(target)) {
                logger.debug("Found 'hashCode' method: " + target);
                return true;
            }
            return false;
        }).intercept(MethodDelegation.to(HashCodeInterceptor.class));

        builder = builder.method(target -> {
            if (ElementMatchers.isEquals().matches(target)) {
                logger.debug("Found 'equals' method: " + target);
                return true;
            }
            return false;
        }).intercept(MethodDelegation.to(EqualsInterceptor.class));

        builder = builder.method(target -> {
            if (!this.advised.isOpaque() && target.getDeclaringType().isInterface() &&
                    target.getDeclaringType().asErasure().isAssignableFrom(Advised.class)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Method is declared on Advised interface: " + target);
                }
                return true;
            }
            return false;
        }).intercept(adviceDispatched);

        return builder;
    }

    /**
     * Allows the generation of a unique key for any generated proxy. By default, a key takes all parameters of this
     * method into account and also remembers the class of this instance.
     *
     * @param rootClass       The root class that is being proxied.
     * @param proxyInterfaces Any additional proxy interfaces.
     * @param exposeProxy     If this proxy is exposed.
     * @param isStatic        If this proxy is static.
     * @param isFrozen        If this proxy is frozen.
     * @return A unique key for the proxy with appropriate implementations of {@link Object#hashCode()} and
     * {@link Object#equals(Object)}.
     */
    protected Object generateCacheKey(Class<?> rootClass,
                                      Class<?>[] proxyInterfaces,
                                      boolean exposeProxy,
                                      boolean isStatic,
                                      boolean isFrozen) {
        return new CacheKey(getClass(), rootClass, proxyInterfaces, exposeProxy, isStatic, isFrozen);
    }

    @Override
    public boolean equals(Object other) {
        return (this == other || (other instanceof ByteBuddyAopProxy &&
                AopProxyUtils.equalsInProxy(this.advised, ((ByteBuddyAopProxy) other).advised)));
    }

    @Override
    public int hashCode() {
        return ByteBuddyAopProxy.class.hashCode() * 13 + this.advised.getTargetSource().hashCode();
    }

    /**
     * A Spring proxy that is generated with Byte Buddy.
     */
    public interface ByteBuddyProxy {

        AdvisedSupport $$_spring_getAdvised();

        void $$_spring_setAdvised(AdvisedSupport advised);
    }

    /**
     * Method interceptor used for static targets with no advice chain. The call
     * is passed directly back to the target. Used when the proxy needs to be
     * exposed and it can't be determined that the method won't return
     * {@code this}.
     */
    public static class StaticUnadvisedInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(ADVISED) AdvisedSupport advised,
                                       @This Object proxy,
                                       @Origin Method method,
                                       @Pipe Function<Object, ?> forward,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (advised == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            Object target = advised.getTargetSource().getTarget();
            Object retVal = forward.apply(target);
            return processReturnType(proxy, target, method, retVal);
        }
    }

    /**
     * Method interceptor used for static targets with no advice chain, when the
     * proxy is to be exposed.
     */
    public static class StaticUnadvisedExposedInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(ADVISED) AdvisedSupport advised,
                                       @This Object proxy,
                                       @Origin Method method,
                                       @Pipe Function<Object, ?> forward,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (advised == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            Object target = advised.getTargetSource().getTarget();
            Object oldProxy = null;
            try {
                oldProxy = AopContext.setCurrentProxy(proxy);
                Object retVal = forward.apply(target);
                return processReturnType(proxy, target, method, retVal);
            } finally {
                AopContext.setCurrentProxy(oldProxy);
            }
        }
    }

    /**
     * Interceptor used to invoke a dynamic target without creating a method
     * invocation or evaluating an advice chain. (We know there was no advice
     * for this method.)
     */
    public static class DynamicUnadvisedInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(ADVISED) AdvisedSupport advised,
                                       @This Object proxy,
                                       @Origin Method method,
                                       @Pipe Function<Object, ?> forward,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (advised == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            TargetSource targetSource = advised.getTargetSource();
            Object target = targetSource.getTarget();
            try {
                Object retVal = forward.apply(target);
                return processReturnType(proxy, target, method, retVal);
            } finally {
                targetSource.releaseTarget(target);
            }
        }
    }

    /**
     * Interceptor for unadvised dynamic targets when the proxy needs exposing.
     */
    public static class DynamicUnadvisedExposedInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(ADVISED) AdvisedSupport advised,
                                       @This Object proxy,
                                       @Origin Method method,
                                       @Pipe Function<Object, ?> forward,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (advised == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            TargetSource targetSource = advised.getTargetSource();
            Object oldProxy = null;
            Object target = targetSource.getTarget();
            try {
                oldProxy = AopContext.setCurrentProxy(proxy);
                Object retVal = forward.apply(target);
                return processReturnType(proxy, target, method, retVal);
            } finally {
                AopContext.setCurrentProxy(oldProxy);
                targetSource.releaseTarget(target);
            }
        }
    }

    public static class ForwardingInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(ADVISED) AdvisedSupport advised,
                                       @Pipe Function<Object, ?> forward,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (advised == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            return forward.apply(advised.getTargetSource().getTarget());
        }
    }

    /**
     * Dispatcher for the {@code equals} method.
     * Ensures that the method call is always handled by this class.
     */
    public static class EqualsInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(ADVISED) AdvisedSupport advised,
                                       @This Object proxy,
                                       @Argument(0) Object other,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (advised == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            if (proxy == other) {
                return true;
            }
            if (other instanceof ByteBuddyProxy) {
                AdvisedSupport otherAdvised = ((ByteBuddyProxy) other).$$_spring_getAdvised();
                return AopProxyUtils.equalsInProxy(advised, otherAdvised);
            } else {
                return false;
            }
        }
    }

    /**
     * Dispatcher for the {@code hashCode} method.
     * Ensures that the method call is always handled by this class.
     */
    public static class HashCodeInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(ADVISED) AdvisedSupport advised,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (advised == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            return ByteBuddyAopProxy.class.hashCode() * 13 + advised.getTargetSource().hashCode();
        }
    }

    /**
     * Interceptor used specifically for advised methods on a frozen, static proxy.
     */
    public static class FixedChainStaticTargetInterceptor implements Serializable {

        private final List<Object> adviceChain;

        public FixedChainStaticTargetInterceptor(List<Object> adviceChain) {
            this.adviceChain = adviceChain;
        }

        @RuntimeType
        public Object intercept(@FieldValue(ADVISED) AdvisedSupport advised,
                                @This Object proxy,
                                @Origin Method method,
                                @AllArguments Object[] args,
                                @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (advised == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            Object target = advised.getTargetSource().getTarget();
            MethodInvocation invocation = new ByteBuddyMethodInvocation(proxy, target, method, args,
                    advised.getTargetClass(), this.adviceChain);
            // If we get here, we need to create a MethodInvocation.
            Object retVal = invocation.proceed();
            retVal = processReturnType(proxy, target, method, retVal);
            return retVal;
        }
    }

    /**
     * General purpose AOP callback. Used when the target is dynamic or when the
     * proxy is not frozen.
     */
    public static class DynamicAdvisedInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(ADVISED) AdvisedSupport advised,
                                       @This Object proxy,
                                       @Origin Method method,
                                       @AllArguments Object[] args,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (advised == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            Object oldProxy = null;
            boolean setProxyContext = false;
            Class<?> targetClass = null;
            Object target = null;
            try {
                if (advised.exposeProxy) {
                    // Make invocation available if necessary.
                    oldProxy = AopContext.setCurrentProxy(proxy);
                    setProxyContext = true;
                }
                // May be null. Get as late as possible to minimize the time we
                // "own" the target, in case it comes from a pool...
                target = advised.getTargetSource().getTarget();
                if (target != null) {
                    targetClass = target.getClass();
                }
                List<Object> chain = advised.getInterceptorsAndDynamicInterceptionAdvice(method, targetClass);
                Object retVal;
                // Check whether we only have one InvokerInterceptor: that is,
                // no real advice, but just reflective invocation of the target.
                if (chain.isEmpty() && Modifier.isPublic(method.getModifiers())) {
                    // We can skip creating a MethodInvocation: just invoke the target directly.
                    // Note that the final invoker must be an InvokerInterceptor, so we know
                    // it does nothing but a reflective operation on the target, and no hot
                    // swapping or fancy proxying.
                    Object[] argsToUse = AopProxyUtils.adaptArgumentsIfNecessary(method, args);
                    try {
                        retVal = method.invoke(target, argsToUse);
                    } catch (InvocationTargetException exception) {
                        throw exception.getCause();
                    }
                } else {
                    // We need to create a method invocation...
                    try {
                        retVal = new ByteBuddyMethodInvocation(proxy, target, method, args, targetClass, chain).proceed();
                    } catch (Throwable throwable) {
                        if (throwable instanceof RuntimeException || throwable instanceof Error) {
                            throw throwable;
                        }
                        for (Class<?> exceptionType : method.getExceptionTypes()) {
                            if (exceptionType.isInstance(throwable)) {
                                throw throwable;
                            }
                        }
                        throw new UndeclaredThrowableException(throwable);
                    }
                }
                retVal = processReturnType(proxy, target, method, retVal);
                return retVal;
            } finally {
                if (target != null) {
                    advised.getTargetSource().releaseTarget(target);
                }
                if (setProxyContext) {
                    // Restore old proxy.
                    AopContext.setCurrentProxy(oldProxy);
                }
            }
        }
    }

    /**
     * Implementation of AOP Alliance MethodInvocation used by this AOP proxy.
     */
    private static class ByteBuddyMethodInvocation extends ReflectiveMethodInvocation {

        private final boolean publicMethod;

        public ByteBuddyMethodInvocation(Object proxy, Object target, Method method, Object[] arguments,
                                         Class<?> targetClass, List<Object> interceptorsAndDynamicMethodMatchers) {

            super(proxy, target, method, arguments, targetClass, interceptorsAndDynamicMethodMatchers);
            this.publicMethod = Modifier.isPublic(method.getModifiers());
        }

        /**
         * Gives a marginal performance improvement versus using reflection to
         * invoke the target when invoking public methods.
         */
        @Override
        protected Object invokeJoinpoint() throws Throwable {
            if (this.publicMethod) {
                try {
                    return this.method.invoke(this.target, this.arguments);
                } catch (InvocationTargetException exception) {
                    throw exception.getCause();
                }
            } else {
                return super.invokeJoinpoint();
            }
        }
    }

    private static class CacheKey {

        private final Class<?> proxyGenerator;

        private final Set<String> types;

        private final boolean exposeProxy;

        private final boolean isStatic;

        private final boolean isFrozen;

        private CacheKey(Class<?> proxyGenerator,
                         Class<?> rootClass,
                         Class<?>[] proxyInterfaces,
                         boolean exposeProxy,
                         boolean isStatic,
                         boolean isFrozen) {
            this.proxyGenerator = proxyGenerator;
            this.types = new HashSet<>();
            this.types.add(rootClass.getName());
            for (Class<?> proxyInterface : proxyInterfaces) {
                this.types.add(proxyInterface.getName());
            }
            this.exposeProxy = exposeProxy;
            this.isStatic = isStatic;
            this.isFrozen = isFrozen;
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) return true;
            if (object == null || getClass() != object.getClass()) return false;
            CacheKey key = (CacheKey) object;
            if (proxyGenerator != key.proxyGenerator) return false;
            if (exposeProxy != key.exposeProxy) return false;
            if (isStatic != key.isStatic) return false;
            if (isFrozen != key.isFrozen) return false;
            return types.equals(key.types);
        }

        @Override
        public int hashCode() {
            int result = types.hashCode();
            result = 31 * result + proxyGenerator.hashCode();
            result = 31 * result + (exposeProxy ? 1 : 0);
            result = 31 * result + (isStatic ? 1 : 0);
            result = 31 * result + (isFrozen ? 1 : 0);
            return result;
        }
    }
}
