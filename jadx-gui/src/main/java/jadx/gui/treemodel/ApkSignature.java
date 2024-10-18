package jadx.gui.treemodel;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.ApkFormatException;

import jadx.api.ICodeInfo;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.gui.JadxWrapper;
import jadx.gui.ui.panel.ApkSignaturePanel;
import jadx.gui.ui.panel.ContentPanel;
import jadx.gui.ui.tab.TabbedPane;
import jadx.gui.utils.UiUtils;

public class ApkSignature extends JNode {
	private static final long serialVersionUID = -9121321926113143407L;

	private static final Logger LOG = LoggerFactory.getLogger(ApkSignature.class);

	private static final ImageIcon CERTIFICATE_ICON = UiUtils.openSvgIcon("nodes/styleKeyPack");

	private final transient File openFile;
	private ICodeInfo content;

	@Nullable
	public static ApkSignature getApkSignature(JadxWrapper wrapper) {
		// Only show the ApkSignature node if an AndroidManifest.xml is present.
		// Without a manifest the Google ApkVerifier refuses to work.
		File apkFile = null;
		for (ResourceFile resFile : wrapper.getResources()) {
			if (resFile.getType() == ResourceType.MANIFEST) {
				ResourceFile.ZipRef zipRef = resFile.getZipRef();
				if (zipRef != null) {
					apkFile = zipRef.getZipFile();
					break;
				}
			}
		}
		if (apkFile == null) {
			return null;
		}
		return new ApkSignature(apkFile);
	}

	public ApkSignature(File openFile) {
		this.openFile = openFile;
	}

	@Override
	public JClass getJParent() {
		return null;
	}

	@Override
	public Icon getIcon() {
		return CERTIFICATE_ICON;
	}

	@Override
	public String makeString() {
		return "APK signature";
	}

	@Override
	public ContentPanel getContentPanel(TabbedPane tabbedPane) {
		// return new HtmlPanel(tabbedPane, this);
		return new ApkSignaturePanel(tabbedPane, this);
	}

	public ApkVerifier.Result getApkVerifierResult() throws ApkFormatException, IOException, NoSuchAlgorithmException {
		ApkVerifier verifier = new ApkVerifier.Builder(openFile).build();
		return verifier.verify();
	}

}
