package io.curity.identityserver.plugin.ica.data.access.attribute

import AttributeValue
import AudienceRestriction
import AuthnContext
import AuthnStatement
import Conditions
import NameID
import Subject
import SubjectConfirmation
import SubjectConfirmationData
import Response
import org.apache.xml.security.c14n.Canonicalizer
import org.apache.xml.security.Init
import com.fasterxml.jackson.dataformat.xml.XmlMapper
import io.curity.identityserver.plugin.ica.data.access.attribute.config.SAMLDataAccessProviderConfiguration
import org.json.JSONArray
import org.json.JSONObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.attribute.AttributeTableView
import se.curity.identityserver.sdk.attribute.Attributes
import se.curity.identityserver.sdk.datasource.AttributeDataAccessProvider
import se.curity.identityserver.sdk.errors.ErrorCode
import standardAttributes
import java.io.ByteArrayOutputStream
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.*
import Attribute as AttributeStatement
import kotlin.random.Random
import org.w3c.dom.Document
import org.w3c.dom.Element
import javax.xml.crypto.dsig.*
import javax.xml.crypto.dsig.dom.DOMSignContext
import javax.xml.crypto.dsig.SignedInfo
import javax.xml.crypto.dsig.Reference
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec
import javax.xml.crypto.dsig.spec.TransformParameterSpec
import javax.xml.parsers.DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.Transformer
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

class SAMLAttributeDataAccessProvider(configuration: SAMLDataAccessProviderConfiguration) : AttributeDataAccessProvider {

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(SAMLAttributeDataAccessProvider::class.java)
        private val xmlMapper = XmlMapper()
    }

    init {
        Init.init()
    }

    private val exceptionFactory = configuration.exceptionFactory
    private val sessionManager = configuration.sessionManager
    private val cryptoStore = configuration.cryptoStore
    private val tokenEndpoint = configuration.tokenEndpoint.get()

    private val privKey = cryptoStore.privateKey
    private val cert = cryptoStore.certificates[0]

    override fun getAttributes(subject: String): AttributeTableView {TODO()}

    override fun getAttributes(subjectMap: MutableMap<*, *>): AttributeTableView? {
        val list: MutableList<Attributes> = mutableListOf()

        val jwtFields = tokenizeJWT(subjectMap["token"].toString())

        val idAss = "_" + generateRandomString(sessionManager.sessionId.length)
        val idRes = "_" + generateRandomString(sessionManager.sessionId.length)

        val assertion = assembleAssertion(jwtFields, id=idAss)
        var response : Response

        var finAss : String
        var finRes : String

        when(subjectMap["signing"].toString()){
            "onlyAssertion" -> {
                logger.info("Assertion signature requested, generating Signature")
                finAss = generateSignature(assertion)
                finRes = generateSignature(null, assembleResponse(jwtFields,assertion,idRes), signRes = false, finAss) // TODO : NOT WORKING YET
            }
            "onlyResponse" -> {
                logger.info("Response signature requested, generating Signature")
                finAss = base64Encode(xmlMapper.writeValueAsBytes(assertion))
                response = assembleResponse(jwtFields, assertion, idRes)
                finRes = generateSignature(null, response, true) // TODO : NOT TESTED
            }
            "both" -> {
                logger.info("Double signature requested, generating signature")
                finAss = generateSignature(assertion)
                response = assembleResponse(jwtFields, assertion, idRes)
                finRes = generateSignature(null, response, true) // TODO : NOT WORKING YET
            }
            else -> {
                finAss = base64Encode(xmlMapper.writeValueAsBytes(assertion))
                response = assembleResponse(jwtFields, assertion, idRes)
                finRes = base64Encode(xmlMapper.writeValueAsBytes(response))
                logger.info("no signature")
            }
        }

        val attribute = Attributes.of("assertion", finAss)
        sessionManager.put(attribute["assertion"])
        val attribute2 = Attributes.of("response", finRes)
        sessionManager.put(attribute2["response"])
        list.add(attribute)
        list.add(attribute2)

        return AttributeTableView.ofAttributes(list)
    }

    private fun assembleResponse(jwtFields: List<String>, assertion: Assertion, id: String) : Response {
        logger.info("Assembling Response")
        val token = JSONObject(base64UrlDecode(jwtFields[1]))

        val iat = unixToISO8601UTC((token.get("iat") as Int).toLong()).toString()

        val response = Response(id, iat)

        response.setIssuer(token.get("samlIssuer").toString())

        response.setAssertion(assertion)

        return response
    }

    private fun assembleAssertion(jwtFields: List<String>, id: String) : Assertion {

        logger.info("Assembling assertion")
        val token = JSONObject(base64UrlDecode(jwtFields[1]))

        val iat = unixToISO8601UTC((token.get("iat") as Int).toLong()).toString()
        val exp = unixToISO8601UTC((token.get("exp") as Int).toLong()).toString()

        val assertion = Assertion(id, iat) // init assertion, convert timestamp to Date

        val audArr = token.get("aud") as JSONArray
        val audList = audArr.toList()

        var aud : String? = ""

        for (field in audList){
            logger.info(field.toString())
            if (field != tokenEndpoint && field != token.get("azp")){
                aud = field.toString()
            }
        }

        // Hardcoded values
        assertion.setIssuer(token.get("samlIssuer").toString())
        assertion.setSubject(
            Subject(
                NameID(token.get("sub").toString()),
                SubjectConfirmation(SubjectConfirmationData("", exp, token.get("samlRecipient").toString()))) // IF USE-CASE for full SAML-flow, must match ID of saml-request
            )
        assertion.setConditions(Conditions(
            AudienceRestriction(aud),
            iat,
            exp
        ))
        assertion.setAuthnStatement(AuthnStatement(
            iat,
            null, // IF USE-CASE for full SAML-flow, must match ID of saml-request
            exp,
            AuthnContext(token.get("amr").toString()) // "https://id.sambi.se/loa/loa3"
        ))

        // Regex to find friendly-name of attributes
        val regex = """^(?:https?:\/\/)?(?:[^\/]+\/)*([^\/]+)$""".toRegex()

        // Ignore standard openid-claims
        for (field in token.toMap()) {
            if (!standardAttributes.contains(field.key)){
                assertion.addAttribute(AttributeStatement(AttributeValue(token.get(field.key).toString()), regex.find(field.key)?.groupValues?.get(1), field.key)) // staticUri
            }
        }

        return assertion
    }

    private fun generateSignature(assertion: Assertion? = null, response: Response? = null, signRes: Boolean = false, signedAss : String = ""): String {

        val streamer = ByteArrayOutputStream()

        val tf: TransformerFactory = TransformerFactory.newInstance()
        val trans: Transformer = tf.newTransformer()

        val signObject = if(signRes || signedAss != ""){
            xmlMapper.writeValueAsString(response).trimIndent()
        }else{
            xmlMapper.writeValueAsString(assertion).trimIndent()
        }

        val dbf = DocumentBuilderFactory.newInstance()
        dbf.isNamespaceAware = true
        val builder: DocumentBuilder = dbf.newDocumentBuilder()
        val doc: Document = builder.parse(signObject.byteInputStream())

        /*
            CODE FOR PARSING ASSERTION INTO RESPONSE : TODO NOT WORKING YET
         */
        if(signedAss != ""){
            val canon : Canonicalizer = Canonicalizer.getInstance(javax.xml.crypto.dsig.CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS)
            val assertionString = xmlMapper.writerWithDefaultPrettyPrinter().writeValueAsString(base64Decode(signedAss)).trimIndent().replace("&lt;", "<").replace("amp;", "").replace("<String>", "").replace("</String>", "").replace("&gt;", ">")
            canon.canonicalize(assertionString.toByteArray(), streamer, false)
            val docAssertion : Document = builder.parse(streamer.toString().byteInputStream())
            //logger.info("STREAMER : $streamer") // STREAMER OUTPUT OF ASSERTION STILL VALID ASSERTION + VALID SIGNATURE
            //logger.info("docAssertion : $docAssertion") // OUTPUT -> [#document: null]
            doc.adoptNode(docAssertion.documentElement)
            streamer.reset()
            if(!signRes){
                trans.transform(DOMSource(doc), StreamResult(streamer))
                return base64Encode(streamer.toByteArray())
            }
        }

        val xsf = XMLSignatureFactory.getInstance("DOM")
        val ref: Reference = xsf.newReference(
            "#" + doc.documentElement.getAttribute("ID"),
            xsf.newDigestMethod(DigestMethod.SHA1, null), listOf(
                xsf.newTransform(Transform.ENVELOPED,
                    null as TransformParameterSpec?
                )
            ), null, null
        )

        var si : SignedInfo = xsf.newSignedInfo(
            xsf.newCanonicalizationMethod(
                CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                null as C14NMethodParameterSpec?
            ),
            xsf.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null), listOf(ref)
        )

        val kif = xsf.keyInfoFactory

        val signatureTemp = xsf.newXMLSignature(si, xsf.keyInfoFactory.newKeyInfo(
            listOf(kif.newX509Data(listOf(cert)))
        ))

        val dsc = DOMSignContext(privKey, doc.documentElement)
        dsc.defaultNamespacePrefix = "ds"
        val element: Element = doc.documentElement as Element
        dsc.setIdAttributeNS(element, null, "ID")

        signatureTemp.sign(dsc)
        trans.transform(DOMSource(doc), StreamResult(streamer))

        return base64Encode(streamer.toString().replace("&#13;","").toByteArray())
    }

    private fun tokenizeJWT(token: String): List<String> {
        val jwtFields = token.split('.')
        if (jwtFields.size != 3)
            throw Exception("Invalid JWT token")
        return jwtFields
    }

    private fun unixToISO8601UTC(s: Long): OffsetDateTime? {
        return Instant.ofEpochSecond(s)
            .atZone(ZoneId.systemDefault())
            .toLocalDateTime().atOffset(ZoneOffset.UTC)
    }

    private fun base64UrlDecode(token: String): String {
        val decodedBytes: ByteArray = Base64.getUrlDecoder().decode(token)
        return String(decodedBytes)
    }

    private fun base64Decode(token: String): String {
        val decodedBytes: ByteArray = Base64.getDecoder().decode(token)
        return String(decodedBytes)
    }

    private fun base64Encode(token: String): String {
        return Base64.getEncoder().encodeToString(token.toByteArray())
    }

    private fun base64Encode(token: ByteArray): String {
        return Base64.getEncoder().encodeToString(token)
    }

    private fun generateRandomString(length: Int): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        val random = Random.Default
        return (1..length)
            .map { chars[random.nextInt(chars.length)] }
            .joinToString("")
    }
}