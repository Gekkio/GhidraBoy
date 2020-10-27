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

import ghidra.app.util.Option;

import javax.swing.*;
import java.awt.*;

public class GameBoyKindOption extends Option {
    private final Component customEditor = createCustomEditor(this);

    public GameBoyKindOption(String name, GameBoyKind value) {
        super(name, GameBoyKind.class, value, null, null);
    }

    public GameBoyKindOption(String group, String name, GameBoyKind value) {
        super(name, GameBoyKind.class, value, null, group);
    }

    public GameBoyKindOption(String name) {
        super(name, GameBoyKind.class, null, null, null);
    }

    public GameBoyKindOption(String name, GameBoyKind value, String arg) {
        super(name, GameBoyKind.class, value, arg, null);
    }

    public GameBoyKindOption(String name, GameBoyKind value, String arg, String group) {
        super(name, GameBoyKind.class, value, arg, group);
    }

    @Override
    public Component getCustomEditorComponent() {
        return this.customEditor;
    }

    @Override
    public Option copy() {
        return new GameBoyKindOption(this.getName(), (GameBoyKind) this.getValue(), this.getArg(), this.getGroup());
    }

    private static Component createCustomEditor(Option option) {
        var panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));

        var gb = new JRadioButton("Game Boy");
        gb.addActionListener(e -> option.setValue(GameBoyKind.GB));
        gb.setSelected(GameBoyKind.GB.equals(option.getValue()));

        var cgb = new JRadioButton("Game Boy Color");
        cgb.addActionListener(e -> option.setValue(GameBoyKind.CGB));
        cgb.setSelected(GameBoyKind.CGB.equals(option.getValue()));

        var group = new ButtonGroup();
        group.add(gb);
        group.add(cgb);
        panel.add(gb);
        panel.add(cgb);
        return panel;
    }
}
