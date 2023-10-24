import com.fasterxml.jackson.annotation.JsonPropertyOrder
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlText

@JsonPropertyOrder("FriendlyName", "Name", "NameFormat", "AttributeValue")
class Attribute(
    attributeValue: MutableList<AttributeValue>,
    friendlyName: String?,
    name: String
) {
    constructor(
        attributeValue: AttributeValue,
        friendlyName: String?,
        name: String
    ) : this(mutableListOf(attributeValue), friendlyName, name)

    @JacksonXmlProperty(isAttribute = true, localName = "FriendlyName")
    private val propOne: String? = friendlyName

    @JacksonXmlProperty(isAttribute = true, localName = "Name")
    private val propTwo: String = name

    @JacksonXmlElementWrapper(useWrapping = false)
    @JacksonXmlProperty(localName = "saml2:AttributeValue")
    private val attributeValue: MutableList<AttributeValue> = attributeValue
}

class AttributeValue(
    value: String,
    format: String = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
    type: String = "xsd:string"
) {
    @JacksonXmlText
    private val text: String = value

    @JacksonXmlProperty(isAttribute = true, localName = "xmlns:xsi")
    private val format: String = format

    @JacksonXmlProperty(isAttribute = true, localName = "xsi:type")
    private val type: String = type
}
