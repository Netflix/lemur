#!/usr/bin/python
from lemur.certificates import service
import os

def createCert(name, tempFolder, exportType):

    lemCert = service.get_by_name(name)
    if not os.path.exists(tempFolder):
        os.mkdir(tempFolder)
    if not os.path.exists('{0}/{1}'.format(tempFolder, lemCert.cn)):
        os.mkdir('{0}/{1}'.format(tempFolder, lemCert.cn))
    certFile = '{0}/{1}/cert.pem'.format(tempFolder, lemCert.cn)
    keyFile = '{0}/{1}/priv.key'.format(tempFolder, lemCert.cn)
    # combine the cert body and chain to create a bundle
    certOut = open(certFile, "w+")
    if exportType == 'NGINX':
        certOut.write(lemCert.body + '\n' + lemCert.chain)
    elif exportType == '3File':
        certOut.write(lemCert.body)
        # chaintOut.write(lemCert.chain)
    else:
        certOut.write(lemCert.body)
    certOut.close()
    keyOut = open(keyFile, "w+")
    keyOut.write(lemCert.private_key)
    keyOut.close()
    return {'certDir': '{0}/{1}'.format(tempFolder, lemCert.cn)}

def copyCert(dstUser, dstHost, dstDir, certDir, options, **kwargs):
    os.system('scp -r {0} {1}@{2}:{3}'.format(certDir, dstUser, dstHost, dstDir))
