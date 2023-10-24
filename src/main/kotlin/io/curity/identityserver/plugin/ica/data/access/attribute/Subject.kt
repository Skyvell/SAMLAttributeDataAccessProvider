import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlText

class Subject(
    NameID: NameID? = null,
    SubjectConfirmation: SubjectConfirmation? = null
) {
    @JacksonXmlProperty(localName = "saml2:NameID")
    private val NameID: NameID? = NameID

    @JacksonXmlProperty(localName = "saml2:SubjectConfirmation")
    private val SubjectConfirmation: SubjectConfirmation? = SubjectConfirmation
}

class NameID(subject: String? = null, Format: String? = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent") {
    @JacksonXmlProperty(isAttribute = true)
    private val Format: String? = Format

    @JacksonXmlText
    private val subject: String? = subject
}

class SubjectConfirmationData(
    InResponseTo: String? = null,
    NotOnOrAfter: String? = null,
    Recipient: String? = null
) {
    @JacksonXmlProperty(isAttribute = true)
    private val InResponseTo: String? = InResponseTo

    @JacksonXmlProperty(isAttribute = true)
    private val NotOnOrAfter: String? = NotOnOrAfter

    @JacksonXmlProperty(isAttribute = true)
    private val Recipient: String? = Recipient
}

class SubjectConfirmation(
    SubjectConfirmationData: SubjectConfirmationData? = null,
    Method: String = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
) {
    @JacksonXmlProperty(localName = "saml2:SubjectConfirmationData")
    private val SubjectConfirmationData: SubjectConfirmationData? = SubjectConfirmationData

    @JacksonXmlProperty(isAttribute = true)
    private val Method: String? = Method
}