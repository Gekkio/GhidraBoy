// Copyright 2019-2020 Joonas Javanainen <joonas.javanainen@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fi.gekkio.ghidraboy;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.HashUtilities;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.regex.Pattern;

public final class Sha256 {
    public final String value;

    private Sha256(String value) {
        this.value = value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Sha256 sha256 = (Sha256) o;
        return value.equals(sha256.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return this.value;
    }

    private static final Pattern SHA256_HEX = Pattern.compile("^[0-9a-z]{64}$");

    public static Sha256 parse(String sha256Hex) {
        if (!SHA256_HEX.matcher(sha256Hex).matches()) {
            throw new IllegalArgumentException("Invalid SHA256 " + sha256Hex);
        }
        return new Sha256(sha256Hex);
    }

    public static Sha256 of(ByteProvider provider) throws IOException {
        try (var stream = provider.getInputStream(0)) {
            return new Sha256(HashUtilities.getHash(HashUtilities.SHA256_ALGORITHM, stream));
        }
    }

    public static Sha256 of(byte[] bytes) throws IOException {
        try (var stream = new ByteArrayInputStream(bytes)) {
            return new Sha256(HashUtilities.getHash(HashUtilities.SHA256_ALGORITHM, stream));
        }
    }
}
