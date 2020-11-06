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

import java.io.IOException;
import java.util.Optional;

public final class RomUtils {
    private RomUtils() {
    }

    private static final Sha256 LOGO_HASH = Sha256.parse("daf4cabdc852baa0291849203f0b41fd0b4ecd58e0d7aff4a509f5de4d7f9a2e");

    public static Optional<GameBoyKind> detectRom(ByteProvider provider) throws IOException {
        if (provider.length() >= 0x150) {
            var logo = provider.readBytes(0x0104, 0x30);
            if (LOGO_HASH.equals(Sha256.of(logo))) {
                var cgbFlag = (short) provider.readByte(0x0143);
                return Optional.of((cgbFlag & 0x80) == 0 ? GameBoyKind.GB : GameBoyKind.CGB);
            }
        }
        return Optional.empty();
    }
}
