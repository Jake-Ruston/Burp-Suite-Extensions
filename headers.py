from burp import IBurpExtender, IScannerCheck, IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		self.headerIssues = HeaderIssues()

		callbacks.setExtensionName("HTTP Headers Analyser")

		callbacks.registerScannerCheck(self)
	
	def doPassiveScan(self, baseRequestResponse):
		issues = []

		headers = self._helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders()
		parsedHeaders = [self.parseHeader(header) for header in headers]
		httpService = baseRequestResponse.getHttpService()

		for header in self.headerIssues.securityHeaders:
			if httpService.getProtocol() == "http" and header == "Strict-Transport-Security":
				continue

			if header not in [h.keys()[0] for h in parsedHeaders if h]:
				functionName = header[0].lower() + header.title().replace("-", "")[1:]
				headerIssue = self.headerIssues[functionName](0)

				issue = CustomScanIssue(
					self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
					headerIssue["title"],
					headerIssue["detail"],
					headerIssue["remediation"],
					headerIssue["background"],
					headerIssue["remediationBackground"],
					[self._callbacks.applyMarkers(baseRequestResponse, None, None)],
					httpService
				)

				issues.append(issue)

		# TODO Add support for inadequate headers
		for header in headers:
			pass

		return issues
	
	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if existingIssue.getIssueName() == newIssue.getIssueName():
			return -1
		
		return 0

	def parseHeader(self, header):
		splitHeader = [h.strip() for h in header.split(":", 1)]

		if len(splitHeader) == 1:
			return {}

		name, value = splitHeader

		return {
			name.title(): value
		}

class CustomScanIssue(IScanIssue):
	
	def __init__(self, url, issueName, issueDetail, remediationDetail, issueBackground, remediationBackground, httpMessages, httpService):
		self._url = url
		self._issueName = issueName
		self._issueDetail = issueDetail
		self._remediationDetail = remediationDetail
		self._issueBackground = issueBackground
		self._remediationBackground = remediationBackground
		self._httpMessages = httpMessages
		self._httpService = httpService

	def getUrl(self):
		return self._url

	def getConfidence(self):
		return "Certain"
	
	def getSeverity(self):
		return "Information"

	def getIssueName(self):
		return self._issueName

	def getIssueDetail(self):
		return self._issueDetail

	def getRemediationDetail(self):
		return self._remediationDetail

	def getIssueBackground(self):
		return self._issueBackground

	def getRemediationBackground(self):
		return self._remediationBackground
	
	def getIssueType(self):
		return 0
	
	def getHttpMessages(self):
		return self._httpMessages
	
	def getHttpService(self):
		return self._httpService

class HeaderIssues():

	def __init__(self):
		self.securityHeaders = {
			"Strict-Transport-Security": self.strictTransportSecurity,
			"X-Frame-Options": self.strictTransportSecurity,
			"X-Content-Type-Options": self.strictTransportSecurity,
			"Content-Security-Policy": self.strictTransportSecurity,
			"X-Permitted-Cross-Domain-Policies": self.strictTransportSecurity,
			"Referrer-Policy": self.strictTransportSecurity,
			"Clear-Site-Data": self.strictTransportSecurity,
			"Cross-Origin-Embedder-Policy": self.strictTransportSecurity,
			"Cross-Origin-Opener-Policy": self.strictTransportSecurity,
			"Cross-Origin-Resource-Policy": self.strictTransportSecurity,
			"Permissions-Policy": self.strictTransportSecurity,
			"Cache-Control": self.strictTransportSecurity,
			"Pragma": self.strictTransportSecurity
		}
	
	def __getitem__(self, item):
		return getattr(self, item)
	
	def strictTransportSecurity(self, option):
		if option == 0:
			return {
				"title": "Missing Strict-Transport-Security HTTP header",
				"detail": "The HTTP response did not set the Strict-Transport-Security header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def xFrameOptions(self, option):
		if option == 0:
			return {
				"title": "Missing X-Frame-Options HTTP header",
				"detail": "The HTTP response did not set the X-Frame-Options header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def xContentTypeOptions(self, option):
		if option == 0:
			return {
				"title": "Missing X-Content-Type-Options HTTP header",
				"detail": "The HTTP response did not set the X-Content-Type-Options header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def contentSecurityPolicy(self, option):
		if option == 0:
			return {
				"title": "Missing Content-Security-Policy HTTP header",
				"detail": "The HTTP response did not set the Content-Security-Policy header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def xPermittedCrossDomainPolicies(self, option):
		if option == 0:
			return {
				"title": "Missing X-Permitted-Cross-Domain-Policies HTTP header",
				"detail": "The HTTP response did not set the X-Permitted-Cross-Domain-Policies header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def referrerPolicy(self, option):
		if option == 0:
			return {
				"title": "Missing Referrer-Policy HTTP header",
				"detail": "The HTTP response did not set the Referrer-Policy header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def clearSiteData(self, option):
		if option == 0:
			return {
				"title": "Missing Clear-Site-Data HTTP header",
				"detail": "The HTTP response did not set the Clear-Site-Data header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def crossOriginEmbedderPolicy(self, option):
		if option == 0:
			return {
				"title": "Missing Cross-Origin-Embedder-Policy HTTP header",
				"detail": "The HTTP response did not set the Cross-Origin-Embedder-Policy header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def crossOriginOpenerPolicy(self, option):
		if option == 0:
			return {
				"title": "Missing Cross-Origin-Opener-Policy HTTP header",
				"detail": "The HTTP response did not set the Cross-Origin-Opener-Policy header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def crossOriginResourcePolicy(self, option):
		if option == 0:
			return {
				"title": "Missing Cross-Origin-Resource-Policy HTTP header",
				"detail": "The HTTP response did not set the Cross-Origin-Resource-Policy header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def permissionsPolicy(self, option):
		if option == 0:
			return {
				"title": "Missing Permissions-Policy HTTP header",
				"detail": "The HTTP response did not set the Permissions-Policy header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def cacheControl(self, option):
		if option == 0:
			return {
				"title": "Missing Cache-Control HTTP header",
				"detail": "The HTTP response did not set the Cache-Control header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
	
	def pragma(self, option):
		if option == 0:
			return {
				"title": "Missing Pragma HTTP header",
				"detail": "The HTTP response did not set the Pragma header.",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
		elif option == 1:
			return {
				"title": "TODO",
				"detail": "TODO",
				"remediation": "TODO",
				"background": "TODO",
				"remediationBackground": "TODO"
			}
