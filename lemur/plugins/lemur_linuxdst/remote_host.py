#!/usr/bin/python
from lemur.certificates import service
import os


def create_cert(name, temp_folder, export_type):

    lem_cert = service.get_by_name(name)
    if not os.path.exists(temp_folder):
        os.mkdir(temp_folder)
    if not os.path.exists('{0}/{1}'.format(temp_folder, lem_cert.cn)):
        os.mkdir('{0}/{1}'.format(temp_folder, lem_cert.cn))
    cert_file = '{0}/{1}/cert.pem'.format(temp_folder, lem_cert.cn)
    key_file = '{0}/{1}/priv.key'.format(temp_folder, lem_cert.cn)
    # combine the cert body and chain to create a bundle
    cert_out = open(cert_file, "w+")
    if export_type == 'NGINX':
        cert_out.write(lem_cert.body + '\n' + lem_cert.chain)
    elif export_type == '3File':
        cert_out.write(lem_cert.body)
        # chaintOut.write(lemCert.chain)
    else:
        cert_out.write(lem_cert.body)
    cert_out.close()
    key_out = open(key_file, "w+")
    key_out.write(lem_cert.private_key)
    key_out.close()
    return {'cert_dir': '{0}/{1}'.format(temp_folder, lem_cert.cn)}


def copy_cert(dst_user, dst_host, dst_dir, cert_dir, options, **kwargs):
    os.system('scp -r {0} {1}@{2}:{3}'.format(cert_dir, dst_user, dst_host, dst_dir))
