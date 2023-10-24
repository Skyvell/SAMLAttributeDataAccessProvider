import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty

class Conditions(
    AudienceRestriction: AudienceRestriction? = null,
    NotBefore: String? = null,
    NotOnOrAfter: String? = null
) {
    @JacksonXmlProperty(isAttribute = true)
    private val NotBefore: String? = NotBefore

    @JacksonXmlProperty(isAttribute = true)
    private val NotOnOrAfter: String? = NotOnOrAfter

    @JacksonXmlProperty(localName = "saml2:AudienceRestriction")
    private val AudienceRestriction: AudienceRestriction? = AudienceRestriction
}

class AudienceRestriction(
    Audience: String?
) {
    @JacksonXmlProperty(localName = "saml2:Audience")
    private val Audience: String? = Audience
}
