package io.curity.identityserver.plugin.ica.data.access.attribute

import Attribute
import AuthnStatement
import Conditions
import Subject
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement

@JacksonXmlRootElement(localName = "saml2:Assertion")
// @JsonPropertyOrder("xmlns:saml2", "xmlns:xsd", "xmlns:xsi", "ID", "IssueInstant", "Version", "Issuer", "Signature", "Subject", "Conditions", "AuthnStatement", "AttributeStatement")
@JsonInclude(JsonInclude.Include.NON_EMPTY)
class Assertion(sessionID: String, iat: String, version: String = "2.0") {
    @JacksonXmlProperty(isAttribute = true, localName = "xmlns:saml2")
    private val propOne: String = "urn:oasis:names:tc:SAML:2.0:assertion"

    @JacksonXmlProperty(isAttribute = true, localName = "ID")
    private val ID: String = sessionID

    @JacksonXmlProperty(isAttribute = true, localName = "IssueInstant")
    private var issueInstant: String = iat

    @JacksonXmlProperty(isAttribute = true, localName = "Version")
    private val Version: String = version

    @JacksonXmlProperty(localName = "saml2:Issuer")
    private var Issuer: String = "testIssuer"

    @JacksonXmlProperty(localName = "saml2:Subject")
    private var Subject: Subject? = null

    @JacksonXmlProperty(localName = "saml2:Conditions")
    private var Conditions: Conditions? = null

    @JacksonXmlProperty(localName = "saml2:AuthnStatement")
    private var AuthnStatement: AuthnStatement? = null

    @JacksonXmlElementWrapper(localName = "saml2:AttributeStatement")
    @JacksonXmlProperty(localName = "saml2:Attribute")
    private val attributes: MutableList<Attribute> = mutableListOf()

    fun setIssuer(issuer: String) {
        Issuer = issuer
    }

    fun setSubject(subject: Subject) {
        Subject = subject
    }

    fun setConditions(conditions: Conditions) {
        Conditions = conditions
    }

    fun setAuthnStatement(authnStatement: AuthnStatement) {
        AuthnStatement = authnStatement
    }

    fun addAttribute(attribute: Attribute) {
        attributes.add(attribute)
    }
}
