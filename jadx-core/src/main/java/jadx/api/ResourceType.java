package jadx.api;

public enum ResourceType {
	CODE(false, ".dex", ".jar", ".class"),
	MANIFEST(false, "AndroidManifest.xml"),
	XML(false, ".xml"),
	ARSC(false, ".arsc"),
	FONT(false, ".ttf"),
	IMG(false, ".png", ".gif", ".jpg"),
	LIB(true, "lib/"),
	ASSET(true, "assets/"),
	UNKNOWN(false);

	private final String[] exts;
	private final String[] starts;

	ResourceType(boolean prefix, String... fixs) {
		this.starts = prefix ? fixs : new String[0];
		this.exts = prefix ? new String[0] : fixs;
	}

	public String[] getExts() {
		return exts;
	}

	public String[] getStarts() {
		return starts;
	}

	public static ResourceType getFileType(String fileName) {
		for (ResourceType type : ResourceType.values()) {
			for (String starts : type.getStarts()) {
				if (fileName.startsWith(starts)) {
					return type;
				}
			}
			for (String ext : type.getExts()) {
				if (fileName.endsWith(ext)) {
					return type;
				}
			}
		}
		return UNKNOWN;
	}

	public static boolean isSupportedForUnpack(ResourceType type) {
		switch (type) {
			case CODE:
			case FONT:
			case UNKNOWN:
				return false;

			case ASSET:
			case LIB:
			case MANIFEST:
			case XML:
			case ARSC:
			case IMG:
				return true;
		}
		return false;
	}
}
