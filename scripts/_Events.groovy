import grails.util.Environment
import groovy.xml.MarkupBuilder
import org.apache.catalina.connector.Connector
import org.apache.catalina.loader.WebappLoader
import org.apache.catalina.startup.Tomcat
import org.apache.coyote.http11.Http11NioProtocol
import org.apache.catalina.Realm

eventConfigureTomcat = { Tomcat tomcat ->

    if (Environment.current == Environment.TEST) {
        return
    }

    String protocol = Http11NioProtocol.name
    Connector connector = new Connector(protocol)
    connector.port = 8443
    connector.protocol = protocol

    def connectorProps = [
            maxSpareThreads     : "75",
            minSpareThreads     : "5",
            SSLEnabled          : "true",
            scheme              : "https",
            secure              : "true",
            enableLookups       : "false",
            clientAuth          : "false",
            sslProtocol         : "TLS",
            keystoreFile        : "/home/me/keys/cbgui.jks",
            keystoreType        : "JKS",
            keystorePass        : "changeit",
            keyAlias            : "ssl_server",
            truststoreFile      : "/home/me/keys/cbgui.jts",
            truststoreType      : "JKS",
            truststorePass      : "changeit",
            SSLVerifyClient     : "optional",
            SSLEngine           : "on",
            SSLVerifyDepth      : "2",
            sslEnabledProtocols : "TLSv1,TLSv1.1,TLSv1.2",
            ciphers             : "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256," +
                                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA," +
                                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384," +
                                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA," +
                                    "TLS_ECDHE_RSA_WITH_RC4_128_SHA," +
                                    "TLS_RSA_WITH_AES_128_CBC_SHA256," +
                                    "TLS_RSA_WITH_AES_128_CBC_SHA," +
                                    "TLS_RSA_WITH_AES_256_CBC_SHA256," +
                                    "TLS_RSA_WITH_AES_256_CBC_SHA," +
                                    "SSL_RSA_WITH_RC4_128_SHA"
    ]

    connectorProps.each { String key, String value ->
        connector.setProperty(key, value)
    }

    tomcat.service.addConnector connector

}

eventWebXmlEnd = { String filename ->

    // add security elements to web.xml, this was previously done via src/templates/web.xml but doing it here
    // programmatically gives us more flexibility, e.g. different config in different environments

    if (Environment.current == Environment.TEST) {
        return
    }

    def lineBreak = System.getProperty("line.separator")

    // this list of URL patterns needs to be manually kept in synch with the URLs that are protected
    def protectedUrlPatterns = [
            '/book/*'
    ].collect {
        "<url-pattern>$it</url-pattern>"
    }.join(lineBreak)


    String securityConfig = """\

    <security-constraint>
        <web-resource-collection>
            <web-resource-name>Protected</web-resource-name>

            ${protectedUrlPatterns}

        </web-resource-collection>
        <auth-constraint>
            <role-name>secureConnection</role-name>
        </auth-constraint>
        <user-data-constraint>
            <transport-guarantee>CONFIDENTIAL</transport-guarantee>
        </user-data-constraint>
    </security-constraint>
    <login-config>
        <auth-method>CLIENT-CERT</auth-method>
    </login-config>
    <security-role>
        <role-name>secureConnection</role-name>
    </security-role>
"""

    def insertAfterTag = { String original, String endTag, String addition ->
        int index = original.indexOf(endTag)
        original.substring(0, index + endTag.length()) +
                addition + original.substring(index + endTag.length())
    }

    String xml = webXmlFile.text
    xml = insertAfterTag(xml, '</error-page>', securityConfig)

    webXmlFile.withWriter { it.write xml }
}
