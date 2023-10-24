package io.curity.identityserver.plugin.ica.data.access.attribute

fun main() {
    val subjectMap = mutableMapOf(
        "signing" to "onlyAssertion",
        "token" to "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE0NTIzNDU0MzYsImF1ZCI6WyJteS1hcHAtaWQtMSIsIm15LWFwcC1pZC0yIl0sImF6cCI6ImNsaWVudEFwcElkIiwic2FtbElzc3VlciI6Imh0dHBzOi8vaWRlbnRpdHlwcm92aWRlci5leGFtcGxlLmNvbS9zYW1sIiwic2FtbFJlY2lwaWVudCI6Imh0dHBzOi8vc2VydmljZXByb3ZpZGVyLmV4YW1wbGUuY29tL2FjcyIsImFtciI6Imh0dHBzOi8vaWQuc2FtYmkuc2UvbG9hL2xvYTMifQ.4aTmQcf5YPQ0olLGBfoa6XWGTcjWkve6bstfsvNUzX8"
    )

    val provider = SAMLAttributeDataAccessProvider()
    val result = provider.getAttributes(subjectMap)
    println("Assertion: ${result[0]}")
    println("\n\n")
    println("Response: ${result[1]}")
}