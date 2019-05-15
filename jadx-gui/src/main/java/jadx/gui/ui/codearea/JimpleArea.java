package jadx.gui.ui.codearea;

import jadx.gui.ui.ContentPanel;

public final class JimpleArea extends AbstractCodeArea {
	private static final long serialVersionUID = -747171470554800028L;

	JimpleArea(ContentPanel contentPanel) {
		super(contentPanel);
		setEditable(false);
	}

	@Override
	public void load() {
		if (getText().isEmpty()) {
			setText(node.getJimple());
			setCaretPosition(0);
		}
	}
}
