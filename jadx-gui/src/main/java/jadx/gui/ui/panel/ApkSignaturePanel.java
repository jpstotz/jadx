package jadx.gui.ui.panel;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JEditorPane;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTree;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;

import com.android.apksig.ApkVerifier.IssueWithParams;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.android.apksig.ApkVerifier;

import jadx.gui.treemodel.ApkSignature;
import jadx.gui.ui.tab.TabbedPane;
import jadx.gui.utils.CertificateManager;
import jadx.gui.utils.NLS;

public class ApkSignaturePanel extends ContentPanel implements TreeSelectionListener {

	private static final Logger log = LoggerFactory.getLogger(ApkSignaturePanel.class);
	private final JTree tree;
	private final JEditorPane textArea;
	private final ApkSigNode root;

	public ApkSignaturePanel(TabbedPane panel, ApkSignature apkSignature) {
		super(panel, apkSignature);
		this.setLayout(new BorderLayout());
		root = new ApkSigNode("APK Signatures");
		tree = new JTree(root);
		textArea = new JEditorPane();
		textArea.setContentType("text/html");
		tree.setMinimumSize(new Dimension(100, 100));
		tree.addTreeSelectionListener(this);

		JScrollPane scrollPaneTree = new JScrollPane(tree);
		JScrollPane scrollPaneTextArea = new JScrollPane(textArea);
		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, scrollPaneTree, scrollPaneTextArea);
		this.add(splitPane, BorderLayout.CENTER);

		ApkVerifier.Result result = null;
		try {
			result = apkSignature.getApkVerifierResult();
		} catch (Exception e) {
			log.error("failed to get APK signature");
			ApkSigNode errorNode = new ApkSigNode("ERROR");
			errorNode.setUserObject(e);
			// TODO: append error and stacktrace to errorNode
			root.add(errorNode);
			throw new RuntimeException(e);
		}
		root.setUserObject(result);
		if (result.isVerified()) {
			root.add(new ApkSigNode(NLS.str("apkSignature.verificationSuccess")));
		} else {
			root.add(new ApkSigNode(NLS.str("apkSignature.verificationFailed")));
		}

		processV1Signatures(result);
		processV2Signatures(result);
		processV3Signatures(result);

		processIssuesNode(root, result.getErrors(), "All Errors");
		processIssuesNode(root, result.getWarnings(), "All Warnings");

		expandAllNodes(tree, 0, tree.getRowCount());
	}

	private void processV1Signatures(ApkVerifier.Result result) {
		List<ApkVerifier.Result.V1SchemeSignerInfo> v1Signer = result.getV1SchemeSigners();
		List<ApkVerifier.Result.V1SchemeSignerInfo> v1Ignored = result.getV1SchemeIgnoredSigners();
		if (v1Signer.isEmpty() && v1Ignored.isEmpty()) {
			return;
		}
		ApkSigNode sigSchemeNode = new ApkSigNode("Signature Scheme v1", v1Signer);
		root.add(sigSchemeNode);
		int i = 1;
		for (ApkVerifier.Result.V1SchemeSignerInfo signerInfo : v1Signer) {
			ApkSigNode signerNode = new ApkSigNode(String.format("Signer %d", i++));
			signerNode.setUserObject(signerInfo);
			sigSchemeNode.add(signerNode);
			processCertificate(signerNode, signerInfo.getCertificate());
			processIssuesNode(signerNode, signerInfo.getErrors(), "Errors");
			processIssuesNode(signerNode, signerInfo.getWarnings(), "Warnings");
		}

		if (!v1Ignored.isEmpty()) {
			ApkSigNode ignoredNode = new ApkSigNode("Ignored Signers");
			ignoredNode.setUserObject(v1Ignored);

			for (ApkVerifier.Result.V1SchemeSignerInfo signerInfo : v1Ignored) {
				processCertificate(ignoredNode, signerInfo.getCertificate());
				processIssuesNode(ignoredNode, signerInfo.getErrors(), "Errors");
				processIssuesNode(ignoredNode, signerInfo.getWarnings(), "Warnings");
			}
		}

	}

	private void processV2Signatures(ApkVerifier.Result result) {
		List<ApkVerifier.Result.V2SchemeSignerInfo> v2Signer = result.getV2SchemeSigners();
		if (v2Signer.isEmpty()) {
			return;
		}
		ApkSigNode sigSchemeNode = new ApkSigNode("Signature Scheme v2", v2Signer);
		root.add(sigSchemeNode);
		int i = 1;
		for (ApkVerifier.Result.V2SchemeSignerInfo signerInfo : v2Signer) {
			ApkSigNode signerNode = new ApkSigNode(String.format("Signer %d", i++));
			signerNode.setUserObject(signerInfo);
			sigSchemeNode.add(signerNode);
			processCertificate(signerNode, signerInfo.getCertificate());
			processCertificateListNode(signerNode, signerInfo.getCertificates());
			processIssuesNode(signerNode, signerInfo.getErrors(), "Errors");
			processIssuesNode(signerNode, signerInfo.getWarnings(), "Warnings");
		}
	}

	private void processV3Signatures(ApkVerifier.Result result) {
		List<ApkVerifier.Result.V3SchemeSignerInfo> v3Signer = result.getV3SchemeSigners();
		if (v3Signer.isEmpty()) {
			return;
		}
		ApkSigNode sigSchemeNode = new ApkSigNode("Signature Scheme v3", v3Signer);
		root.add(sigSchemeNode);
		int i = 1;
		for (ApkVerifier.Result.V3SchemeSignerInfo signerInfo : v3Signer) {
			ApkSigNode signerNode = new ApkSigNode(String.format("Signer %d", i++));
			signerNode.setUserObject(signerInfo);
			sigSchemeNode.add(signerNode);
			processCertificate(signerNode, signerInfo.getCertificate());
			processCertificateListNode(signerNode, signerInfo.getCertificates());
			processIssuesNode(signerNode, signerInfo.getErrors(), "Errors");
			processIssuesNode(signerNode, signerInfo.getWarnings(), "Warnings");
		}

	}

	private void processIssuesNode(ApkSigNode parentNode, List<ApkVerifier.IssueWithParams> issueList, String issueType) {
		if (issueList.isEmpty()) {
			return;
		}
		ApkSigNode issuesNode = new ApkSigNode(String.format("%s (%d)", issueType, issueList.size()));
		issuesNode.setUserObject(new IssuesObject(issueType, issueList));
		parentNode.add(issuesNode);
	}

	private void processCertificate(ApkSigNode parentNode, X509Certificate cert) {
		if (cert == null) {
			return;
		}
		ApkSigNode treeNode = new ApkSigNode("Certificate: " + cert.getSubjectDN());
		treeNode.setUserObject(cert);
		parentNode.add(treeNode);
	}

	private void processCertificateListNode(ApkSigNode parentNode, List<X509Certificate> certList) {
		if (certList.size() <= 1) {
			return;
		}
		ApkSigNode certListNode = new ApkSigNode("Certificate Chain");
		parentNode.add(certListNode);
		certListNode.setUserObject(certList);
		for (X509Certificate cert : certList) {
			processCertificate(certListNode, cert);
		}
	}

	private void expandAllNodes(JTree tree, int startingIndex, int rowCount) {
		for (int i = startingIndex; i < rowCount; ++i) {
			tree.expandRow(i);
		}

		if (tree.getRowCount() != rowCount) {
			expandAllNodes(tree, rowCount, tree.getRowCount());
		}
	}

	@Override
	public void loadSettings() {

	}

	@Override
	public void valueChanged(TreeSelectionEvent e) {
		ApkSigNode treeNode = (ApkSigNode) tree.getLastSelectedPathComponent();
		if (treeNode == null || treeNode.getUserObject() == null) {
			textArea.setText("");
			return;
		}
		Object userObject = treeNode.getUserObject();

		StringEscapeUtils.Builder builder = StringEscapeUtils.builder(StringEscapeUtils.ESCAPE_HTML4);

		writeObject(builder, userObject);
		textArea.setText(builder.toString());
		textArea.setCaretPosition(0);
	}

	private static class ApkSigNode extends DefaultMutableTreeNode {

		private final String name;

		public ApkSigNode(String name) {
			this.name = name;
		}

		public ApkSigNode(String name, Object userObject) {
			super(userObject);
			this.name = name;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	private static class IssuesObject {
		private final String issueType;
		private final List<ApkVerifier.IssueWithParams> issueList;

		public IssuesObject(String issueType, List<IssueWithParams> issueList) {
			this.issueType = issueType;
			this.issueList = issueList;
		}
	}

	private void writeObject(StringEscapeUtils.Builder builder, Object object) {
		if (object instanceof ApkVerifier.Result) {
			writeResult(builder, (ApkVerifier.Result) object);
		} else if (object instanceof Certificate) {
			writeCertificate(builder, (Certificate) object);
		} else if (object instanceof List) {
			writeList(builder, (List<Object>) object);
		} else if (object instanceof IssuesObject) {
			IssuesObject issuesObject = (IssuesObject) object;
			writeIssues(builder, issuesObject.issueType, issuesObject.issueList);
		} else if (object instanceof Throwable) {
			writeThrowable(builder, (Throwable) object);
		}
	}

	private void writeList(StringEscapeUtils.Builder builder, List<Object> list) {
		for (Object entry : list) {
			writeObject(builder, entry);
		}
	}

	private void writeResult(StringEscapeUtils.Builder builder, ApkVerifier.Result result) {
		builder.append("<h1>APK signature verification result:</h1>");

		builder.append("<p><b>");
		if (result.isVerified()) {
			builder.escape(NLS.str("apkSignature.verificationSuccess"));
		} else {
			builder.escape(NLS.str("apkSignature.verificationFailed"));
		}
		builder.append("</b></p>");

		final String err = NLS.str("apkSignature.errors");
		final String warn = NLS.str("apkSignature.warnings");
		final String sigSuccKey = "apkSignature.signatureSuccess";
		final String sigFailKey = "apkSignature.signatureFailed";

		writeIssues(builder, err, result.getErrors());

		if (!result.getV1SchemeSigners().isEmpty()) {
			builder.append("<h2>");
			builder.escape(NLS.str(result.isVerifiedUsingV1Scheme() ? sigSuccKey : sigFailKey, 1));
			builder.append("</h2>\n");

			builder.append("<blockquote>");
			for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeSigners()) {
				builder.append("<h3>");
				builder.escape(NLS.str("apkSignature.signer"));
				builder.append(" ");
				builder.escape(signer.getName());
				builder.append(" (");
				builder.escape(signer.getSignatureFileName());
				builder.append(")");
				builder.append("</h3>");
				writeCertificate(builder, signer.getCertificate());
				writeIssues(builder, err, signer.getErrors());
				writeIssues(builder, warn, signer.getWarnings());
			}
			builder.append("</blockquote>");
		}
		if (!result.getV2SchemeSigners().isEmpty()) {
			builder.append("<h2>");
			builder.escape(NLS.str(result.isVerifiedUsingV2Scheme() ? sigSuccKey : sigFailKey, 2));
			builder.append("</h2>\n");

			builder.append("<blockquote>");
			for (ApkVerifier.Result.V2SchemeSignerInfo signer : result.getV2SchemeSigners()) {
				builder.append("<h3>");
				builder.escape(NLS.str("apkSignature.signer"));
				builder.append(" ");
				builder.append(Integer.toString(signer.getIndex() + 1));
				builder.append("</h3>");
				writeCertificate(builder, signer.getCertificate());
				writeIssues(builder, err, signer.getErrors());
				writeIssues(builder, warn, signer.getWarnings());
			}
			builder.append("</blockquote>");
		}
		if (!result.getV3SchemeSigners().isEmpty()) {
			builder.append("<h2>");
			builder.escape(NLS.str(result.isVerifiedUsingV3Scheme() ? sigSuccKey : sigFailKey, 3));
			builder.append("</h2>\n");

			builder.append("<blockquote>");
			for (ApkVerifier.Result.V3SchemeSignerInfo signer : result.getV3SchemeSigners()) {
				builder.append("<h3>");
				builder.escape(NLS.str("apkSignature.signer"));
				builder.append(" ");
				builder.append(Integer.toString(signer.getIndex() + 1));
				builder.append("</h3>");
				writeCertificate(builder, signer.getCertificate());
				writeIssues(builder, err, signer.getErrors());
				writeIssues(builder, warn, signer.getWarnings());
			}
			builder.append("</blockquote>");
		}
		writeIssues(builder, warn, result.getWarnings());
	}

	private void writeThrowable(StringEscapeUtils.Builder builder, Throwable t) {
		builder.append("<h1>");
		builder.escape(NLS.str("apkSignature.exception"));
		builder.append("</h1><pre>");
		builder.escape(ExceptionUtils.getStackTrace(t));
		builder.append("</pre>");
	}

	private void writeCertificate(StringEscapeUtils.Builder builder, Certificate cert) {
		CertificateManager certMgr = new CertificateManager(cert);
		builder.append("<blockquote><pre>");
		builder.escape(certMgr.generateHeader());
		builder.append("</pre><pre>");
		builder.escape(certMgr.generatePublicKey());
		builder.append("</pre><pre>");
		builder.escape(certMgr.generateSignature());
		builder.append("</pre><pre>");
		builder.append(certMgr.generateFingerprint());
		builder.append("</pre></blockquote>");
	}

	private void writeIssues(StringEscapeUtils.Builder builder, String issueType, List<ApkVerifier.IssueWithParams> issueList) {
		if (issueList.isEmpty()) {
			return;
		}
		builder.append("<h3>");
		builder.escape(issueType);
		builder.append("</h3>");
		builder.append("<blockquote>");
		// Unprotected Zip entry issues are very common, handle them separately
		List<ApkVerifier.IssueWithParams> unprotIssues = issueList.stream()
				.filter(i -> i.getIssue() == ApkVerifier.Issue.JAR_SIG_UNPROTECTED_ZIP_ENTRY)
				.collect(Collectors.toList());
		if (!unprotIssues.isEmpty()) {
			builder.append("<h4>");
			builder.escape(NLS.str("apkSignature.unprotectedEntry"));
			builder.append("</h4><blockquote>");
			for (ApkVerifier.IssueWithParams issue : unprotIssues) {
				builder.escape((String) issue.getParams()[0]);
				builder.append("<br>");
			}
			builder.append("</blockquote>");
		}
		List<ApkVerifier.IssueWithParams> remainingIssues = issueList.stream()
				.filter(i -> i.getIssue() != ApkVerifier.Issue.JAR_SIG_UNPROTECTED_ZIP_ENTRY)
				.collect(Collectors.toList());
		if (!remainingIssues.isEmpty()) {
			builder.append("<pre>\n");
			for (ApkVerifier.IssueWithParams issue : remainingIssues) {
				builder.escape(issue.toString());
				builder.append("\n");
			}
			builder.append("</pre>\n");
		}
		builder.append("</blockquote>");
	}
}
