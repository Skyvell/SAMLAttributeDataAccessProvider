import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement
import io.curity.identityserver.plugin.ica.data.access.attribute.Assertion

@JacksonXmlRootElement(localName = "samlp:Response")
// @JsonPropertyOrder("xmlns:saml2", "xmlns:xsd", "xmlns:xsi", "ID", "IssueInstant", "Version", "Issuer", "Signature", "Subject", "Conditions", "AuthnStatement", "AttributeStatement")
@JsonInclude(JsonInclude.Include.NON_EMPTY)
class Response(sessionID: String, iat: String, requestID: String = "", version: String = "2.0") {
    @JacksonXmlProperty(isAttribute = true, localName = "xmlns:samlp")
    private val propZero: String = "urn:oasis:names:tc:SAML:2.0:protocol"

    @JacksonXmlProperty(isAttribute = true, localName = "xmlns:saml2")
    private val propOne: String = "urn:oasis:names:tc:SAML:2.0:assertion"

    @JacksonXmlProperty(isAttribute = true, localName = "xmlns:xsd")
    private val propTwo: String = "http://www.w3.org/2001/XMLSchema"

    @JacksonXmlProperty(isAttribute = true, localName = "xmlns:xsi")
    private val propThree: String = "http://www.w3.org/2001/XMLSchema-instance"

    @JacksonXmlProperty(isAttribute = true, localName = "ID")
    private val ID: String = sessionID

    @JacksonXmlProperty(isAttribute = true, localName = "IssueInstant")
    private var issueInstant: String = iat

    @JacksonXmlProperty(isAttribute = true, localName = "InResponseTo")
    private var inResponseTo: String = requestID

    @JacksonXmlProperty(isAttribute = true, localName = "Version")
    private val Version: String = version

    @JacksonXmlProperty(localName = "saml2:Issuer")
    private var Issuer: String = "testIssuer"

    @JacksonXmlProperty(localName = "samlp:Status")
    private var Status: Status? = Status()

    @JacksonXmlProperty(localName = "saml2:Assertion")
    private var Assertion: Assertion? = null

    fun setIssuer(issuer: String) {
        Issuer = issuer
    }

    fun setAssertion(assertion: Assertion) {
        Assertion = assertion
    }

    fun signAssertion() {
        TODO()
    }

    fun signResponse() {
        TODO()
    }
}

class Status() {
    @JacksonXmlProperty(localName = "samlp:StatusCode")
    private val StatusCode: StatusCode = StatusCode()
}

class StatusCode() {
    @JacksonXmlProperty(isAttribute = true)
    private val value: String = "urn:oasis:names:tc:SAML:2.0:status:Success"
}