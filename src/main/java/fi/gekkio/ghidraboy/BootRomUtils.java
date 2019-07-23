// Copyright 2019 Joonas Javanainen <joonas.javanainen@gmail.com>
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

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import static ghidra.util.HashUtilities.getHash;

public final class BootRomUtils {
    private BootRomUtils() {
    }

    private static final String[] GB_ROMS = {
            "26e71cf01e301e5dc40e987cd2ecbf6d0276245890ac829db2a25323da86818e", // DMG0
            "cf053eccb4ccafff9e67339d4e78e98dce7d1ed59be819d2a1ba2232c6fce1c7", // DMG
            "0e4ddff32fc9d1eeaae812a157dd246459b00c9e14f2f61751f661f32361e360", // SGB
            "a8cb5f4f1f16f2573ed2ecd8daedb9c5d1dd2c30a481f9b179b5d725d95eafe2", // MGB
            "fd243c4fb27008986316ce3df29e9cfbcdc0cd52704970555a8bb76edbec3988", // SGB2
    };
    private static final String[] CGB_ROMS = {
            "3a307a41689bee99a9a32ea021bf45136906c86b2e4f06c806738398e4f92e45", // CGB0
            "b4f2e416a35eef52cba161b159c7c8523a92594facb924b3ede0d722867c50c7", // CGB
    };

    public static Optional<GameBoyKind> detectBootRom(ByteProvider provider) throws IOException {
        if (provider.length() == 0x100) {
            var hash = getHash(HashUtilities.SHA256_ALGORITHM, provider.getInputStream(0));
            if (Arrays.stream(GB_ROMS).anyMatch(known -> known.equals(hash))) {
                return Optional.of(GameBoyKind.GB);
            }
        } else if (provider.length() == 0x900) {
            var hash = getHash(HashUtilities.SHA256_ALGORITHM, provider.getInputStream(0));
            if (Arrays.stream(CGB_ROMS).anyMatch(known -> known.equals(hash))) {
                return Optional.of(GameBoyKind.CGB);
            }
        }
        return Optional.empty();
    }
}
