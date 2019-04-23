/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.beans.factory.support;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.NamingStrategy;
import net.bytebuddy.TypeCache;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.MethodDelegation;
import net.bytebuddy.implementation.bind.annotation.*;
import net.bytebuddy.matcher.ElementMatchers;
import org.springframework.beans.BeanInstantiationException;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.util.StringUtils;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.concurrent.Callable;

public class ByteBuddySubclassingInstantiationStrategy extends SimpleInstantiationStrategy {

    private static final String BEAN_DEFINITION = "beanDefinition";

    private static final String OWNER = "owner";

    @Override
    protected Object instantiateWithMethodInjection(RootBeanDefinition bd, String beanName, BeanFactory owner) {
        return instantiateWithMethodInjection(bd, beanName, owner, null);
    }

    @Override
    protected Object instantiateWithMethodInjection(RootBeanDefinition bd, String beanName, BeanFactory owner,
                                                    Constructor<?> ctor, Object... args) {

        return new ByteBuddySubclassCreator(bd, owner).instantiate(ctor, args);
    }

    private static class ByteBuddySubclassCreator {

        private static final TypeCache<CacheKey> cache = new TypeCache.WithInlineExpunction<>(TypeCache.Sort.SOFT);

        private final RootBeanDefinition beanDefinition;

        private final BeanFactory owner;

        ByteBuddySubclassCreator(RootBeanDefinition beanDefinition, BeanFactory owner) {
            this.beanDefinition = beanDefinition;
            this.owner = owner;
        }

        /**
         * Create a new instance of a dynamically generated subclass implementing the
         * required lookups.
         *
         * @param ctor constructor to use. If this is {@code null}, use the
         *             no-arg constructor (no parameterization, or Setter Injection)
         * @param args arguments to use for the constructor.
         *             Ignored if the {@code ctor} parameter is {@code null}.
         * @return new instance of the dynamically generated subclass
         */
        public Object instantiate(Constructor<?> ctor, Object... args) {
            Class<?> subclass = getOrCreateEnhancedSubclass(this.beanDefinition);
            ByteBuddyBeanProxy instance;
            if (ctor == null) {
                instance = (ByteBuddyBeanProxy) BeanUtils.instantiateClass(subclass);
            } else {
                try {
                    Constructor<?> enhancedSubclassConstructor = subclass.getConstructor(ctor.getParameterTypes());
                    instance = (ByteBuddyBeanProxy) enhancedSubclassConstructor.newInstance(args);
                } catch (Exception ex) {
                    throw new BeanInstantiationException(this.beanDefinition.getBeanClass(),
                            "Failed to invoke constructor for CGLIB enhanced subclass [" + subclass.getName() + "]", ex);
                }
            }

            instance.$$_spring_setBeanDefinition(this.beanDefinition);
            instance.$$_spring_setOwner(this.owner);

            return instance;
        }


        private Class<?> getOrCreateEnhancedSubclass(RootBeanDefinition beanDefinition) {
            ClassLoader classLoader = beanDefinition.getClass().getClassLoader();
            CacheKey key = new CacheKey(beanDefinition.getClass().getName());

            return cache.findOrInsert(classLoader, key, () -> createEnhancedSubclass(beanDefinition, classLoader), cache);
        }

        private Class<?> createEnhancedSubclass(RootBeanDefinition beanDefinition, ClassLoader classLoader) {
            return new ByteBuddy()
                    .with(TypeValidation.DISABLED)
                    .with(new NamingStrategy.SuffixingRandom("SpringBean"))
                    .subclass(beanDefinition.getBeanClass())
                    .method(target -> {
                        Method method = ((MethodDescription.ForLoadedMethod) target.asDefined()).getLoadedMethod();
                        MethodOverride methodOverride = beanDefinition.getMethodOverrides().getOverride(method);
                        return methodOverride instanceof LookupOverride;
                    })
                    .intercept(MethodDelegation.to(LookupOverrideMethodInterceptor.class))
                    .method(target -> {
                        Method method = ((MethodDescription.ForLoadedMethod) target.asDefined()).getLoadedMethod();
                        MethodOverride methodOverride = beanDefinition.getMethodOverrides().getOverride(method);
                        return methodOverride instanceof ReplaceOverride;
                    })
                    .intercept(MethodDelegation.to(ReplaceOverrideMethodInterceptor.class))
                    .defineField(BEAN_DEFINITION, RootBeanDefinition.class, Visibility.PRIVATE)
                    .defineField(OWNER, BeanFactory.class, Visibility.PRIVATE)
                    .implement(ByteBuddyBeanProxy.class)
                    .method(ElementMatchers.named("$$_spring_setBeanDefinition"))
                    .intercept(FieldAccessor.ofField(BEAN_DEFINITION))
                    .method(ElementMatchers.named("$$_spring_setOwner"))
                    .intercept(FieldAccessor.ofField(OWNER))
                    .make()
                    .load(classLoader)
                    .getLoaded();
        }

        private static class CacheKey {

            private final String name;

            public CacheKey(String name) {
                this.name = name;
            }

            @Override
            public boolean equals(Object object) {
                if (this == object) return true;
                if (object == null || getClass() != object.getClass()) return false;
                CacheKey cacheKey = (CacheKey) object;
                return name.equals(cacheKey.name);
            }

            @Override
            public int hashCode() {
                return name.hashCode();
            }
        }
    }


    public static class LookupOverrideMethodInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(BEAN_DEFINITION) RootBeanDefinition beanDefinition,
                                       @FieldValue(OWNER) BeanFactory owner,
                                       @Origin Method method,
                                       @AllArguments Object[] args,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (beanDefinition == null || owner == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            // Cast is safe, as CallbackFilter filters are used selectively.
            LookupOverride lo = (LookupOverride) beanDefinition.getMethodOverrides().getOverride(method);
            Object[] argsToUse = (args.length > 0 ? args : null);  // if no-arg, don't insist on args at all
            if (StringUtils.hasText(lo.getBeanName())) {
                return owner.getBean(lo.getBeanName(), argsToUse);
            } else {
                return owner.getBean(method.getReturnType(), argsToUse);
            }
        }
    }


    public static class ReplaceOverrideMethodInterceptor {

        @RuntimeType
        public static Object intercept(@FieldValue(BEAN_DEFINITION) RootBeanDefinition beanDefinition,
                                       @FieldValue(OWNER) BeanFactory owner,
                                       @This Object self,
                                       @Origin Method method,
                                       @AllArguments Object[] args,
                                       @SuperCall(nullIfImpossible = true) Callable<?> superCall) throws Throwable {
            if (beanDefinition == null || owner == null) {
                if (superCall == null) {
                    throw new AbstractMethodError();
                } else {
                    return superCall.call();
                }
            }
            ReplaceOverride ro = (ReplaceOverride) beanDefinition.getMethodOverrides().getOverride(method);
            // TODO could cache if a singleton for minor performance optimization
            MethodReplacer mr = owner.getBean(ro.getMethodReplacerBeanName(), MethodReplacer.class);
            return mr.reimplement(self, method, args);
        }
    }

    public interface ByteBuddyBeanProxy {

        void $$_spring_setBeanDefinition(RootBeanDefinition beanDefinition);

        void $$_spring_setOwner(BeanFactory owner);
    }
}
