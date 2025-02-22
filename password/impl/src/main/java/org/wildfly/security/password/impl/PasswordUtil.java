/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.password.impl;

import org.wildfly.common.Assert;

/**
 * Helper utility methods for operations on passwords.
 *
 * @author <a href="mailto:jpkroehling.javadoc@redhat.com">Juraci Paixão Kröhling</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class PasswordUtil {

    private static final ThreadLocalSecureRandom THREAD_LOCAL_SECURE_RANDOM = new ThreadLocalSecureRandom();

    /**
     * Generate a random salt as byte array.
     *
     * @param saltSize the size of the salt
     * @return a byte array representing the random salt
     */
    public static byte[] generateRandomSalt(int saltSize) {
        byte[] randomSalt = new byte[saltSize];
        THREAD_LOCAL_SECURE_RANDOM.get().nextBytes(randomSalt);
        return randomSalt;
    }

    /**
     * Generate a random salt as int.
     *
     * @return a byte array representing the random salt
     */
    static int generateRandomSaltInt() {
        byte[] saltBytes = generateRandomSalt(4);
        return convertBytesToInt(saltBytes);
    }

    static int convertBytesToInt(byte[] saltBytes) {
        Assert.assertTrue(saltBytes.length == 4);
        return (saltBytes[0] & 0xff) << 24 | (saltBytes[1] & 0xff) << 16 | (saltBytes[2] & 0xff) << 8 | saltBytes[3] & 0xff;
    }
}
