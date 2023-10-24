import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty

class AuthnStatement(
    AuthnInstant: String? = null,
    SessionIndex: String? = null,
    SessionNotOnOrAfter: String? = null,
    AuthnContext: AuthnContext? = null
) {
    @JacksonXmlProperty(isAttribute = true)
    private val AuthnInstant: String? = AuthnInstant

    @JacksonXmlProperty(isAttribute = true)
    private val SessionIndex: String? = SessionIndex

    @JacksonXmlProperty(isAttribute = true)
    private val SessionNotOnOrAfter: String? = SessionNotOnOrAfter

    @JacksonXmlProperty(localName = "saml2:AuthnContext")
    private val AuthnContext: AuthnContext? = AuthnContext
}

class AuthnContext(
    AuthnContextClassRef: String? = null
) {
    @JacksonXmlProperty(localName = "saml2:AuthnContextClassRef")
    private val AuthnContextClassRef: String? = AuthnContextClassRef
}