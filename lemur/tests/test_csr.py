TEST_CSR = """
                # Configuration for standard CSR generation for Netflix
                # Used for procuring VeriSign certificates
                # Author: jachan
                # Contact: cloudsecurity@netflix.com

                [ req ]
                # Use a 2048 bit private key
                default_bits       = 2048
                default_keyfile    = key.pem
                prompt             = no
                encrypt_key        = no

                # base request
                distinguished_name = req_distinguished_name

                # extensions
                # Uncomment the following line if you are requesting a SAN cert
                {is_san_comment}req_extensions     = req_ext

                # distinguished_name
                [ req_distinguished_name ]
                countryName            = "US"                     # C=
                stateOrProvinceName    = "CALIFORNIA"                 # ST=
                localityName           = "Los Gatos"                 # L=
                organizationName       = "Netflix, Inc."        # O=
                organizationalUnitName = "Operations"          # OU=
                # This is the hostname/subject name on the certificate
                commonName             = "{DNS[0]}"            # CN=

                [ req_ext ]
                # Uncomment the following line if you are requesting a SAN cert
                {is_san_comment}subjectAltName          = @alt_names

                [alt_names]
                # Put your SANs here
                {DNS_LINES}
            """
