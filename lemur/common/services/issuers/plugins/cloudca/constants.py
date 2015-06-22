CSR_CONFIG = """
                # Configuration for standard CSR generation for Netflix
                # Used for procuring CloudCA certificates
                # Author: kglisson
                # Contact: secops@netflix.com

                [ req ]
                # Use a 2048 bit private key
                default_bits       = 2048
                default_keyfile    = key.pem
                prompt             = no
                encrypt_key        = no

                # base request
                distinguished_name = req_distinguished_name

                # distinguished_name
                [ req_distinguished_name ]
                countryName            = "{country}"                     # C=
                stateOrProvinceName    = "{state}"                 # ST=
                localityName           = "{location}"                 # L=
                organizationName       = "{organization}"        # O=
                organizationalUnitName = "{organizationalUnit}"        # OU=
                # This is the hostname/subject name on the certificate
                commonName             = "{commonName}"            # CN=
            """

